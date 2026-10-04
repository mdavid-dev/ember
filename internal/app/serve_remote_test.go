package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPKI struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
	pool                                                 *x509.CertPool
}

func writeTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	write := func(name, typ string, der []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
		return path
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ember test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		return write(cn+".pem", "CERTIFICATE", der), write(cn+"-key.pem", "EC PRIVATE KEY", keyDER)
	}

	p := testPKI{caFile: write("ca.pem", "CERTIFICATE", caDER), pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	p.serverCert, p.serverKey = leaf(2, "server", x509.ExtKeyUsageServerAuth)
	p.clientCert, p.clientKey = leaf(3, "alice-laptop", x509.ExtKeyUsageClientAuth)
	return p
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startRemoteServer(t *testing.T, cfg *config) (string, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	cfg.logger = slog.New(slog.NewTextHandler(logs, nil))
	cfg.serveRemote = true
	cfg.daemon = true
	if cfg.interval == 0 {
		cfg.interval = time.Second
	}
	if cfg.logSource == nil {
		cfg.logSource = stubLogSource{}
	}
	if cfg.relayed == nil {
		cfg.relayed = fetcher.NewHTTPFetcher("http://127.0.0.1:1", 0)
	}
	srv := newMetricsServer("127.0.0.1:0", newMetricsHandler(freshHolder(), cfg, map[string]time.Duration{"": cfg.interval}))
	require.NoError(t, configureExposeServer(srv, cfg))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { stopMetricsServer(srv) })
	return "https://" + ln.Addr().String(), logs
}

func tlsClient(pool *x509.CertPool, certs ...tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: certs,
	}}}
}

func getWithAuth(t *testing.T, c *http.Client, url, user, pass string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "ember-test/1.0")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestValidate_ServeRemote(t *testing.T) {
	pki := writeTestPKI(t)
	base := func() *config {
		return &config{daemon: true, expose: ":9191", interval: time.Second, addrsRaw: []string{"http://localhost:2019"}, serveRemote: true}
	}
	tests := []struct {
		name    string
		mutate  func(*config)
		wantErr string
	}{
		{"without auth", func(*config) {}, "--serve-remote requires --metrics-auth or --expose-client-ca"},
		{"without daemon", func(c *config) { c.daemon, c.expose, c.metricsAuth = false, "", "" }, "--serve-remote requires --daemon"},
		{"cert without key", func(c *config) { c.metricsAuth, c.exposeCert = "u:p", pki.serverCert }, "--expose-cert and --expose-key must be set together"},
		{"key without cert", func(c *config) { c.metricsAuth, c.exposeKey = "u:p", pki.serverKey }, "--expose-cert and --expose-key must be set together"},
		{"client CA without TLS", func(c *config) { c.exposeCA = pki.caFile }, "--expose-client-ca requires --expose-cert and --expose-key"},
		{"basic auth", func(c *config) { c.metricsAuth = "u:p" }, ""},
		{"mTLS only", func(c *config) { c.exposeCert, c.exposeKey, c.exposeCA = pki.serverCert, pki.serverKey, pki.caFile }, ""},
		{"TLS without daemon", func(c *config) { c.daemon, c.exposeCert, c.exposeKey = false, pki.serverCert, pki.serverKey }, "--expose-cert requires --daemon"},
		{"several --addr", func(c *config) {
			c.metricsAuth, c.addrsRaw = "u:p", []string{"web1=http://localhost:2019", "web2=http://localhost:2020"}
		}, "--serve-remote relays a single Caddy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(cfg)
			err := validate(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

type stubLogSource struct{}

func (stubLogSource) Since(int64, int) ([]fetcher.LogEntry, int64, error) { return nil, 0, nil }

// countingAdmin stands for Caddy's admin API and counts what reaches it.
type countingAdmin struct {
	mu   sync.Mutex
	seen []string
}

func (a *countingAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.seen = append(a.seen, r.Method+" "+r.URL.Path)
	a.mu.Unlock()
	switch r.URL.Path {
	case "/frankenphp/threads":
		http.Error(w, "no FrankenPHP here", http.StatusNotFound)
		return
	case "/config/apps/pki/certificate_authorities":
		http.Error(w, `{"error":"invalid traversal path at: config/apps/pki/certificate_authorities"}`, http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte("{}"))
}

func (a *countingAdmin) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

func newCountingAdmin(t *testing.T) (*countingAdmin, *fetcher.HTTPFetcher) {
	t.Helper()
	admin := &countingAdmin{}
	srv := httptest.NewServer(admin)
	t.Cleanup(srv.Close)
	return admin, fetcher.NewHTTPFetcher(srv.URL, 0)
}

func TestNewMetricsHandler_RemoteRoutesNeedServeRemote(t *testing.T) {
	_, hf := newCountingAdmin(t)
	for _, serveRemote := range []bool{false, true} {
		cfg := &config{interval: time.Second, serveRemote: serveRemote, logSource: stubLogSource{}, relayed: hf}
		h := newMetricsHandler(freshHolder(), cfg, nil)
		for _, path := range []string{"/logs", "/caddy/config/", "/certificates"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			want := http.StatusNotFound
			if serveRemote {
				want = http.StatusOK
			}
			assert.Equal(t, want, rec.Code, "%s, serveRemote=%t", path, serveRemote)
		}
	}
}

func TestConfigureExposeServer_WarnsWithoutTLS(t *testing.T) {
	logs := &syncBuffer{}
	cfg := &config{serveRemote: true, metricsAuth: "u:p", logger: slog.New(slog.NewTextHandler(logs, nil))}
	srv := &http.Server{Handler: http.NotFoundHandler()}

	require.NoError(t, configureExposeServer(srv, cfg))

	assert.Nil(t, srv.TLSConfig)
	assert.Contains(t, logs.String(), "clear text")
}

func TestServeRemote_BasicAuthOverTLS(t *testing.T) {
	pki := writeTestPKI(t)
	admin, hf := newCountingAdmin(t)
	url, logs := startRemoteServer(t, &config{
		metricsAuth: "remote-user:s3cret-pass",
		exposeCert:  pki.serverCert,
		exposeKey:   pki.serverKey,
		relayed:     hf,
	})
	refused := tlsClient(pki.pool)
	for _, path := range []string{"/caddy/metrics", "/caddy/config/", "/logs?after=-1"} {
		assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+path, "", ""), path)
	}
	assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+"/caddy/metrics", "wrong-user", "wrong-pass"))
	refused.CloseIdleConnections()
	assert.Empty(t, admin.requests(), "nothing reaches Caddy without the credentials")

	client := tlsClient(pki.pool)
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/caddy/metrics", "remote-user", "s3cret-pass"))
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/logs?after=-1", "remote-user", "s3cret-pass"))
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/logs?after=0", "remote-user", "s3cret-pass"))
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/metrics", "remote-user", "s3cret-pass"))
	client.CloseIdleConnections()
	assert.Equal(t, []string{"GET /metrics"}, admin.requests())

	require.Eventually(t, func() bool {
		return strings.Count(logs.String(), `msg="remote request refused"`) == 4 &&
			strings.Contains(logs.String(), "remote session opened")
	}, 2*time.Second, 10*time.Millisecond)
	out := logs.String()
	assert.Contains(t, out, "status=401")
	assert.Equal(t, 1, strings.Count(out, `msg="remote session opened"`), "only the first request of a TUI opens a session")
	assert.Contains(t, out, "user_agent=ember-test/1.0")
	for _, secret := range []string{"remote-user", "s3cret-pass", "wrong-user", "wrong-pass"} {
		assert.NotContains(t, out, secret)
	}
}

func TestServeRemote_TracesTheRelayRefusals(t *testing.T) {
	pki := writeTestPKI(t)
	admin, hf := newCountingAdmin(t)
	url, logs := startRemoteServer(t, &config{
		metricsAuth: "remote-user:s3cret-pass",
		exposeCert:  pki.serverCert,
		exposeKey:   pki.serverKey,
		relayed:     hf,
	})
	client := tlsClient(pki.pool)
	t.Cleanup(client.CloseIdleConnections)

	assert.Equal(t, http.StatusForbidden, getWithAuth(t, client, url+"/caddy/debug/pprof/", "remote-user", "s3cret-pass"))
	req, err := http.NewRequest(http.MethodPost, url+"/caddy/frankenphp/workers/restart", nil)
	require.NoError(t, err)
	req.SetBasicAuth("remote-user", "s3cret-pass")
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, http.StatusNotFound, getWithAuth(t, client, url+"/caddy/frankenphp/threads", "remote-user", "s3cret-pass"))
	assert.Equal(t, http.StatusBadRequest, getWithAuth(t, client, url+"/caddy/config/apps/pki/certificate_authorities", "remote-user", "s3cret-pass"))

	assert.Equal(t, []string{"GET /frankenphp/threads", "GET /config/apps/pki/certificate_authorities"}, admin.requests(), "only the TUI reads reached Caddy")
	require.Eventually(t, func() bool {
		return strings.Count(logs.String(), `msg="remote request refused"`) == 2
	}, 2*time.Second, 10*time.Millisecond)
	out := logs.String()
	assert.Contains(t, out, "method=GET path=/caddy/debug/pprof/ status=403")
	assert.Contains(t, out, "method=POST path=/caddy/frankenphp/workers/restart status=405")
	assert.NotContains(t, out, "/caddy/frankenphp/threads", "Caddy's own 404 is an answer, not a refusal")
	assert.NotContains(t, out, "/caddy/config/apps/pki", "nor is its 400 for a PKI app it does not have")
}

type refusingLogSource struct{}

func (refusingLogSource) Since(int64, int) ([]fetcher.LogEntry, int64, error) {
	return nil, 0, errors.New("logs are not available: Caddy is on another host and the daemon has no --log-listen")
}

func TestServeRemote_TracesASessionWithoutLogs(t *testing.T) {
	pki := writeTestPKI(t)
	url, logs := startRemoteServer(t, &config{
		metricsAuth: "remote-user:s3cret-pass",
		exposeCert:  pki.serverCert,
		exposeKey:   pki.serverKey,
		logSource:   refusingLogSource{},
	})
	client := tlsClient(pki.pool)
	t.Cleanup(client.CloseIdleConnections)

	assert.Equal(t, http.StatusConflict, getWithAuth(t, client, url+"/logs?after=-1", "remote-user", "s3cret-pass"))

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "remote session opened") }, 2*time.Second, 10*time.Millisecond)
	assert.Contains(t, logs.String(), "path=/logs status=409", "the refusal of the logs is traced too")
}

func TestServeRemote_ClientCARequiresCertificate(t *testing.T) {
	pki := writeTestPKI(t)
	url, logs := startRemoteServer(t, &config{
		exposeCert: pki.serverCert,
		exposeKey:  pki.serverKey,
		exposeCA:   pki.caFile,
	})

	resp, err := tlsClient(pki.pool).Get(url + "/metrics")
	if err == nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "a client without certificate must fail the handshake")
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "TLS handshake error") }, 2*time.Second, 10*time.Millisecond)

	cert, err := tls.LoadX509KeyPair(pki.clientCert, pki.clientKey)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, getWithAuth(t, tlsClient(pki.pool, cert), url+"/logs?after=-1", "", ""))
	assert.Contains(t, logs.String(), "client_cn=alice-laptop")
}

func newTestRemoteLogs(t *testing.T, cfg *config, hf *fetcher.HTTPFetcher) *remoteLogs {
	t.Helper()
	cfg.logger = slog.New(slog.DiscardHandler)
	l := newRemoteLogs(cfg, hf)
	l.lease = 300 * time.Millisecond
	t.Cleanup(l.Close)
	return l
}

func TestRemoteLogs_LeaseInstallsThenRestoresCaddy(t *testing.T) {
	api := newFakeCaddyLogAPI(t)
	t.Cleanup(api.srv.Close)
	api.addServer("srv0", "")
	l := newTestRemoteLogs(t, &config{addrs: []addrSpec{{url: api.srv.URL}}}, fetcher.NewHTTPFetcher(api.srv.URL, 0))
	assert.Zero(t, api.putCount(), "nothing is installed before a TUI asks for the logs")

	_, next, err := l.Since(-1, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, api.putCount())
	assert.JSONEq(t, "{}", api.serverLogs("srv0"))

	conn, err := net.Dial("tcp", api.registeredAddr(t))
	require.NoError(t, err)
	_, err = conn.Write([]byte(`{"level":"info","logger":"http.log.access.log0","msg":"handled"}` + "\n"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return l.buf.Len() == 1 }, 2*time.Second, 10*time.Millisecond)
	entries, next, err := l.Since(next, 0)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "handled", entries[0].Message)
	joined, joinedNext, err := l.Since(-1, 0)
	require.NoError(t, err)
	assert.Empty(t, joined, "a TUI joining a running session starts from now")
	assert.Equal(t, next, joinedNext)

	for range 10 {
		time.Sleep(l.lease / 6)
		_, _, err = l.Since(next, 0)
		require.NoError(t, err)
	}
	assert.False(t, api.unregistered.Load(), "every request extends the lease")

	require.Eventually(t, func() bool {
		return api.unregistered.Load() && api.serverDeleteCount("srv0") == 1
	}, 2*time.Second, 10*time.Millisecond, "Caddy is restored once the lease expires")
	assert.Empty(t, api.serverLogs("srv0"))
	assert.Zero(t, l.buf.Len(), "the lines do not outlive the session")

	_, _, err = l.Since(next, 0)
	require.NoError(t, err)
	assert.Equal(t, 4, api.putCount(), "the next request opens a new session")
}

func TestRemoteLogs_UnavailableWithoutLogListen(t *testing.T) {
	cfg := &config{addrs: []addrSpec{{url: "http://prod.example.com:2019"}}}

	_, _, err := newTestRemoteLogs(t, cfg, fetcher.NewHTTPFetcher(cfg.addrs[0].url, 0)).Since(0, 0)

	require.ErrorContains(t, err, "--log-listen")
}

func TestRunDaemon_ServesLogsAndRestoresCaddyOnShutdown(t *testing.T) {
	api := newFakeCaddyLogAPI(t)
	t.Cleanup(api.srv.Close)
	api.addServer("srv0", "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	expose := ln.Addr().String()
	require.NoError(t, ln.Close())
	cfg := &config{
		addrs:       []addrSpec{{url: api.srv.URL}},
		interval:    time.Second,
		expose:      expose,
		daemon:      true,
		serveRemote: true,
		metricsAuth: "remote:s3cret",
		logger:      slog.New(slog.DiscardHandler),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instances, err := newInstances(ctx, cfg, "v-test")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, instances, cfg, nil) }()

	req, err := http.NewRequest(http.MethodGet, "http://"+cfg.expose+"/logs", nil)
	require.NoError(t, err)
	req.SetBasicAuth("remote", "s3cret")
	require.Eventually(t, func() bool {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)
	assert.Equal(t, 2, api.putCount())

	cancel()
	require.NoError(t, <-done)

	assert.True(t, api.unregistered.Load(), "an orderly stop removes the sinks")
	assert.Equal(t, 1, api.serverDeleteCount("srv0"))
	_, _, err = cfg.logSource.Since(0, 0)
	require.ErrorContains(t, err, "stopping")
	assert.Equal(t, 2, api.putCount(), "nothing is installed after the stop")
}
