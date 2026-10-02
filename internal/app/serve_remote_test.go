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

	"github.com/alexandre-daubois/ember/internal/exporter"
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

func TestValidate_ExposeCertRequiresDaemon(t *testing.T) {
	cfg := &config{expose: ":9191", interval: time.Second, addrsRaw: []string{"http://localhost:2019"}, exposeCert: "c.pem", exposeKey: "k.pem"}
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--expose-cert requires --daemon")
}

type stubLogSource struct{}

func (stubLogSource) Since(int64, int) ([]fetcher.LogEntry, int64, error) { return nil, 0, nil }

func TestNewMetricsHandler_SnapshotRouteNeedsServeRemote(t *testing.T) {
	for _, serveRemote := range []bool{false, true} {
		cfg := &config{interval: time.Second, serveRemote: serveRemote, logSource: stubLogSource{},
			instSources: map[string]exporter.InstanceSource{"": fetcher.NewHTTPFetcher("http://127.0.0.1:1", 0)}}
		rec := httptest.NewRecorder()
		newMetricsHandler(freshHolder(), cfg, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/snapshot", nil))
		certs := httptest.NewRecorder()
		newMetricsHandler(freshHolder(), cfg, nil).ServeHTTP(certs, httptest.NewRequest(http.MethodGet, "/certificates?source=pki", nil))
		logs := httptest.NewRecorder()
		newMetricsHandler(freshHolder(), cfg, nil).ServeHTTP(logs, httptest.NewRequest(http.MethodGet, "/logs", nil))
		caddyConfig := httptest.NewRecorder()
		newMetricsHandler(freshHolder(), cfg, nil).ServeHTTP(caddyConfig, httptest.NewRequest(http.MethodGet, "/config", nil))
		if serveRemote {
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, http.StatusOK, certs.Code)
			assert.Equal(t, http.StatusOK, logs.Code)
			assert.Equal(t, http.StatusBadGateway, caddyConfig.Code, "no Caddy behind the daemon")
		} else {
			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.Equal(t, http.StatusNotFound, certs.Code)
			assert.Equal(t, http.StatusNotFound, logs.Code)
			assert.Equal(t, http.StatusNotFound, caddyConfig.Code)
		}
	}

	rec := httptest.NewRecorder()
	cfg := &config{interval: time.Second, serveRemote: true}
	newMetricsHandler(freshHolder(), cfg, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/snapshot", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestConfigureExposeServer_BadTLSMaterialFails(t *testing.T) {
	pki := writeTestPKI(t)
	bad := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not a cert"), 0o600))
	log := slog.New(slog.DiscardHandler)

	for name, cfg := range map[string]*config{
		"missing cert": {exposeCert: "/nonexistent.pem", exposeKey: pki.serverKey, logger: log},
		"mismatched":   {exposeCert: pki.serverCert, exposeKey: pki.clientKey, logger: log},
		"bad CA":       {exposeCert: pki.serverCert, exposeKey: pki.serverKey, exposeCA: bad, logger: log},
	} {
		err := configureExposeServer(&http.Server{}, cfg)
		require.Error(t, err, name)
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
	url, logs := startRemoteServer(t, &config{
		metricsAuth: "remote-user:s3cret-pass",
		exposeCert:  pki.serverCert,
		exposeKey:   pki.serverKey,
	})
	refused := tlsClient(pki.pool)
	assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+"/snapshot", "", ""))
	assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+"/snapshot", "wrong-user", "wrong-pass"))
	assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+"/certificates?source=pki", "", ""))
	assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+"/logs", "", ""))
	assert.Equal(t, http.StatusUnauthorized, getWithAuth(t, refused, url+"/config", "", ""))
	refused.CloseIdleConnections()

	client := tlsClient(pki.pool)
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/snapshot", "remote-user", "s3cret-pass"))
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/snapshot?after=0001-01-01T00:00:00Z", "remote-user", "s3cret-pass"))
	assert.Equal(t, http.StatusOK, getWithAuth(t, client, url+"/metrics", "remote-user", "s3cret-pass"))
	client.CloseIdleConnections()

	require.Eventually(t, func() bool {
		return strings.Count(logs.String(), `msg="remote request refused"`) == 5 &&
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
	assert.Equal(t, http.StatusOK, getWithAuth(t, tlsClient(pki.pool, cert), url+"/snapshot", "", ""))
	assert.Contains(t, logs.String(), "client_cn=alice-laptop")
}

func TestCertSources_KeyedLikeTheHolder(t *testing.T) {
	single := []*instance{{name: "web"}}
	assert.Contains(t, instanceSources(single), "")

	multi := []*instance{{name: "web1"}, {name: "web2"}}
	sources := instanceSources(multi)
	assert.Contains(t, sources, "web1")
	assert.Contains(t, sources, "web2")
}

func newTestRemoteLogs(t *testing.T, cfg *config, instances []*instance) *remoteLogs {
	t.Helper()
	cfg.logger = slog.New(slog.DiscardHandler)
	l := newRemoteLogs(cfg, instances)
	l.lease = 300 * time.Millisecond
	t.Cleanup(l.Close)
	return l
}

func TestRemoteLogs_LeaseInstallsThenRestoresCaddy(t *testing.T) {
	api := newFakeCaddyLogAPI(t)
	t.Cleanup(api.srv.Close)
	api.addServer("srv0", "")
	l := newTestRemoteLogs(t, &config{addrs: []addrSpec{{url: api.srv.URL}}},
		[]*instance{{name: "test", fetcher: fetcher.NewHTTPFetcher(api.srv.URL, 0)}})
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

func TestRemoteLogs_Unavailable(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config
		instances []*instance
		want      string
	}{
		{"multi-instance", &config{addrs: []addrSpec{{url: "http://localhost:2019"}, {url: "http://localhost:2020"}}},
			[]*instance{{name: "web1"}, {name: "web2"}}, "multi-instance daemon"},
		{"remote Caddy without --log-listen", &config{addrs: []addrSpec{{url: "http://prod.example.com:2019"}}},
			[]*instance{{name: "prod"}}, "--log-listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := newTestRemoteLogs(t, tt.cfg, tt.instances).Since(0, 0)
			require.ErrorContains(t, err, tt.want)
		})
	}
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
