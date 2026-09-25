package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func remotePreRun(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newRootCmd("test")
	require.NoError(t, cmd.ParseFlags(args))
	return cmd.PersistentPreRunE(cmd, nil)
}

func TestPrepareRemote_Incompatibilities(t *testing.T) {
	for flag, args := range map[string][]string{
		"--daemon":     {"--daemon", "--expose", ":9191"},
		"--json":       {"--json"},
		"--expose":     {"--expose", ":9191"},
		"--log-listen": {"--log-listen", ":9210"},
		"--stdin-logs": {"--stdin-logs"},
	} {
		err := remotePreRun(t, append([]string{"--remote", "https://prod:9191"}, args...)...)
		require.Error(t, err, flag)
		assert.Contains(t, err.Error(), "--remote is incompatible with "+flag)
	}
}

func TestPrepareRemote_RejectsBadURLAndAuth(t *testing.T) {
	err := remotePreRun(t, "--remote", "prod:9191")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://")

	err = remotePreRun(t, "--remote", "https://prod:9191", "--remote-auth", "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user:password")
}

func TestRemoteFromEnv_IgnoredByDaemonAndJSON(t *testing.T) {
	t.Setenv("EMBER_REMOTE", "https://prod:9191")
	require.NoError(t, remotePreRun(t, "--json"))
	require.NoError(t, remotePreRun(t, "--daemon", "--expose", ":9191"))

	err := remotePreRun(t, "--json", "--remote", "https://prod:9191")
	require.Error(t, err, "an explicit --remote still conflicts")
	assert.Contains(t, err.Error(), "--remote is incompatible with --json")
}

func TestPrepareRemote_RefusesPlainHTTPOutsideLocalhost(t *testing.T) {
	cmd := newRootCmd("test")
	for remote, refused := range map[string]bool{
		"http://prod:9191":      true,
		"http://127.0.0.1:9191": false,
		"http://localhost:9191": false,
		"http://[::1]:9191":     false,
		"https://prod:9191":     false,
	} {
		cfg := &config{remote: remote, logger: slog.New(slog.DiscardHandler)}
		err := prepareRemote(cmd, cfg)
		if refused {
			require.Error(t, err, remote)
			assert.Contains(t, err.Error(), "only accepted for localhost", remote)
		} else {
			require.NoError(t, err, remote)
		}
	}
}

func TestPrepareRemote_IgnoresAddrWithAWarning(t *testing.T) {
	cmd := newRootCmd("test")
	require.NoError(t, cmd.ParseFlags([]string{"--addr", "http://elsewhere:2019"}))
	logs := &syncBuffer{}
	cfg := &config{remote: "https://prod:9191", logger: slog.New(slog.NewTextHandler(logs, nil))}

	require.NoError(t, prepareRemote(cmd, cfg))

	assert.Contains(t, logs.String(), "ignored with --remote")
}

func TestPrepareRemote_ExportedAddrNeverBlocks(t *testing.T) {
	t.Setenv("EMBER_ADDR", "ftp://nope")
	err := remotePreRun(t)
	require.Error(t, err, "the local mode rejects this address")

	t.Setenv("EMBER_REMOTE", "https://prod:9191")
	err = remotePreRun(t)
	require.NoError(t, err)
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func TestRemote_EndToEndOverTLS(t *testing.T) {
	var mu sync.Mutex
	methods := map[string]int{}
	count := 0
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods[r.Method]++
		count += 10
		n := count
		mu.Unlock()
		if r.URL.Path != "/metrics" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `# TYPE caddy_http_request_duration_seconds histogram
caddy_http_request_duration_seconds_bucket{server="srv0",le="+Inf"} %d
caddy_http_request_duration_seconds_sum{server="srv0"} %d
caddy_http_request_duration_seconds_count{server="srv0"} %d
`, n, n/10, n)
	}))
	t.Cleanup(caddy.Close)

	pki := writeTestPKI(t)
	cfg := &config{
		addrs:       []addrSpec{{url: caddy.URL}},
		interval:    200 * time.Millisecond,
		expose:      freePort(t),
		daemon:      true,
		serveRemote: true,
		metricsAuth: "remote:s3cret",
		exposeCert:  pki.serverCert,
		exposeKey:   pki.serverKey,
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	instances, err := newInstances(ctx, cfg, "v-test")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, instances, cfg, nil) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	tlsCfg, err := fetcher.BuildTLSConfig(fetcher.TLSOptions{CACert: pki.caFile})
	require.NoError(t, err)
	u, err := url.Parse("https://" + cfg.expose)
	require.NoError(t, err)
	f := fetcher.NewRemoteFetcher(u, "remote:s3cret", tlsCfg, "test")
	t.Cleanup(f.CloseIdleConnections)

	require.Eventually(t, func() bool {
		interval, err := f.Interval(ctx)
		return err == nil && interval == cfg.interval
	}, 5*time.Second, 50*time.Millisecond)

	var state model.State
	var last time.Time
	var rps float64
	for range 4 {
		snap, err := f.Fetch(ctx)
		require.NoError(t, err)
		require.True(t, snap.FetchedAt.After(last))
		last = snap.FetchedAt
		state.Update(snap)
		rps = max(rps, state.Derived.RPS)
	}

	assert.Positive(t, rps)
	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, methods, 1, "the daemon only reads from Caddy")
	assert.Contains(t, methods, http.MethodGet)
}
