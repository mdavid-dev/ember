package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/exporter"
	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/alexandre-daubois/ember/internal/ui"
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

	err = remotePreRun(t, "--remote", "https://prod:9191?instance=web1")
	require.Error(t, err, "a --serve-remote daemon has a single Caddy")
	assert.Contains(t, err.Error(), "without a query")

	err = remotePreRun(t, "--remote", "https://prod:9191", "--interval", "10ms")
	require.Error(t, err, "the TUI polls at its own --interval")
	assert.Contains(t, err.Error(), "--interval must be at least")
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
		cfg := &config{remote: remote, interval: time.Second, logger: slog.New(slog.DiscardHandler)}
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
	cfg := &config{remote: "https://prod:9191", interval: time.Second, logger: slog.New(slog.NewTextHandler(logs, nil))}

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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	expose := ln.Addr().String()
	require.NoError(t, ln.Close())
	cfg := &config{
		addrs:       []addrSpec{{url: caddy.URL}},
		interval:    200 * time.Millisecond,
		expose:      expose,
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

	u, err := url.Parse("https://" + cfg.expose)
	require.NoError(t, err)
	f := fetcher.NewRemoteFetcher(u, "remote:s3cret", "test")
	require.NoError(t, configureTLS(f.HTTPFetcher, fetcher.TLSOptions{CACert: pki.caFile}))
	t.Cleanup(f.CloseIdleConnections)

	var state model.State
	require.Eventually(t, func() bool {
		snap, err := f.Fetch(ctx)
		if err != nil {
			return false
		}
		state.Update(snap)
		return state.Derived.RPS > 0
	}, 5*time.Second, 150*time.Millisecond, "the TUI's own fetcher reads Caddy through the daemon")
	require.ErrorContains(t, f.RestartWorkers(ctx), "HTTP 405")

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, methods, 1, "the daemon only reads from Caddy")
	assert.Contains(t, methods, http.MethodGet)
}

type recordingLogSource struct {
	buf *model.LogBuffer
	err error

	mu      sync.Mutex
	cursors []int64
}

func (s *recordingLogSource) Since(after int64, limit int) ([]fetcher.LogEntry, int64, error) {
	s.mu.Lock()
	s.cursors = append(s.cursors, after)
	s.mu.Unlock()
	if s.err != nil {
		return nil, 0, s.err
	}
	entries, next := s.buf.Since(after, limit)
	return entries, next, nil
}

func (s *recordingLogSource) seen() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.cursors)
}

func remoteLogsAgainst(t *testing.T, h http.Handler, interval time.Duration) *ui.Config {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := fetcher.NewRemoteFetcher(u, "", "test")
	t.Cleanup(f.CloseIdleConnections)
	cfg := &config{remoteURL: u}
	cfg.remotePage, cfg.logsRefusal = f.FetchLogs(context.Background(), -1)
	uiCfg := &ui.Config{Interval: interval}
	t.Cleanup(setupLogSource(cfg, f, uiCfg))
	return uiCfg
}

func logMessages(b *model.LogBuffer) []string {
	entries, _ := b.Since(0, 0)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Message)
	}
	return out
}

func TestRemoteLogs_ClientSortsEveryLineOnceInOrder(t *testing.T) {
	src := &recordingLogSource{buf: model.NewLogBuffer(0)}
	var access, runtime []string
	for i := range 2500 {
		e := fetcher.LogEntry{Logger: "http.handlers.reverse_proxy", Message: strconv.Itoa(i)}
		if i%2 == 0 {
			e = fetcher.LogEntry{Logger: "http.log.access.log0", Message: strconv.Itoa(i), Host: "shop.test", Method: "GET", URI: "/p/" + strconv.Itoa(i), Status: 200}
			access = append(access, e.Message)
		} else {
			runtime = append(runtime, e.Message)
		}
		src.buf.Append(e)
	}

	uiCfg := remoteLogsAgainst(t, exporter.LogsHandler(src), time.Hour)

	require.NotNil(t, uiCfg.LogBuffer)
	require.Eventually(t, func() bool {
		return uiCfg.LogBuffer.Len()+uiCfg.RuntimeLogBuffer.Len() == 2500
	}, 900*time.Millisecond, 10*time.Millisecond, "a full page is followed at once, not at the next tick")
	assert.Equal(t, []int64{-1, 1000, 2000}, src.seen())
	assert.Equal(t, access, logMessages(uiCfg.LogBuffer))
	assert.Equal(t, runtime, logMessages(uiCfg.RuntimeLogBuffer))
	assert.Positive(t, uiCfg.RouteAggregator.BucketCount())
	assert.Empty(t, uiCfg.LogSource)
}

func TestRemoteLogs_ClientRetriesAfterAServerError(t *testing.T) {
	src := &recordingLogSource{buf: model.NewLogBuffer(0)}
	src.buf.Append(fetcher.LogEntry{Logger: "admin.api", Message: "before the outage"})
	logs := exporter.LogsHandler(src)
	var requests atomic.Int32

	uiCfg := remoteLogsAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 2 {
			src.buf.Append(fetcher.LogEntry{Logger: "admin.api", Message: "after the outage"})
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		logs.ServeHTTP(w, r)
	}), 100*time.Millisecond)

	require.Eventually(t, func() bool { return uiCfg.RuntimeLogBuffer.Len() == 2 }, 2*time.Second, 10*time.Millisecond, "a 5xx in a session is retried")
	assert.Equal(t, []string{"before the outage", "after the outage"}, logMessages(uiCfg.RuntimeLogBuffer))
	assert.Equal(t, int64(-1), src.seen()[0])
	assert.NotContains(t, src.seen()[1:], int64(-1), "only the first request opens the session")
}

func TestRemoteLogs_ClientMarksTheEndOfTheStream(t *testing.T) {
	src := &recordingLogSource{buf: model.NewLogBuffer(0)}
	src.buf.Append(fetcher.LogEntry{Logger: "admin.api", Message: "before the stop"})
	logs := exporter.LogsHandler(src)
	var requests atomic.Int32

	uiCfg := remoteLogsAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			http.Error(w, "logs are not available: the daemon is stopping", http.StatusConflict)
			return
		}
		logs.ServeHTTP(w, r)
	}), 100*time.Millisecond)

	require.Eventually(t, func() bool { return uiCfg.RuntimeLogBuffer.Len() == 2 }, 2*time.Second, 10*time.Millisecond)
	last, _ := uiCfg.RuntimeLogBuffer.Since(1, 0)
	assert.Equal(t, "ember.remote", last[0].Logger)
	assert.Equal(t, "error", last[0].Level)
	assert.Contains(t, last[0].Message, "remote log stream stopped: daemon answered 409 Conflict: logs are not available: the daemon is stopping")
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, int32(2), requests.Load(), "a refusal ends the polling")
}

func TestRemoteLogs_ClientStopsOnARefusal(t *testing.T) {
	src := &recordingLogSource{err: errors.New("logs are not available on a multi-instance daemon")}

	uiCfg := remoteLogsAgainst(t, exporter.LogsHandler(src), 100*time.Millisecond)

	assert.Nil(t, uiCfg.LogBuffer, "the tab keeps its message")
	assert.Contains(t, uiCfg.LogsRefusal, "multi-instance daemon")
	assert.Len(t, src.seen(), 1)
}

func TestRemoteLogs_TheTUIInstallsNoSink(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	logs := exporter.LogsHandler(&recordingLogSource{buf: model.NewLogBuffer(0)})

	remoteLogsAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		logs.ServeHTTP(w, r)
	}), 100*time.Millisecond)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) >= 3
	}, 2*time.Second, 10*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, r := range seen {
		assert.Equal(t, "GET /logs", r, "the daemon handles the sinks; the TUI only reads its logs")
	}
}

func TestRunRemote_ExitsBeforeTheTUI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := "http://" + ln.Addr().String()
	require.NoError(t, ln.Close())
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(refusing.Close)

	run := func(raw string) (*url.URL, error) {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		return u, runRemote(context.Background(), &config{remoteURL: u, remoteAuth: "remote:wrong", interval: time.Second}, "test")
	}

	u, err := run(closed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote daemon "+u.Host+": ")
	assert.NotErrorAs(t, err, new(fetcher.RefusedError), "no daemon answered")

	u, err = run(refusing.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote daemon "+u.Host+": the daemon rejected the credentials")
}

func TestRemoteFatal(t *testing.T) {
	assert.False(t, remoteFatal(nil))
	assert.False(t, remoteFatal(fetcher.RefusedError{Status: http.StatusConflict}), "the logs alone are refused: the TUI starts")
	assert.True(t, remoteFatal(fetcher.RefusedError{Status: http.StatusNotFound}), "no --serve-remote daemon there")
	assert.True(t, remoteFatal(fetcher.RefusedError{Status: http.StatusUnauthorized}))
	assert.True(t, remoteFatal(errors.New("daemon answered 502 Bad Gateway")))
}
