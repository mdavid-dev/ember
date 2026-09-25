package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestValidateRemote(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{"nothing set", config{}, ""},
		{"client", config{remote: "https://ember.prod", remoteToken: "short is fine client-side"}, ""},
		{"server", config{daemon: true, expose: ":9443", remoteToken: testToken}, ""},
		{"server over TLS with mTLS", config{daemon: true, expose: ":9443", remoteToken: testToken, exposeCert: "c", exposeKey: "k", exposeClientCA: "ca"}, ""},
		{"client without token", config{remote: "https://ember.prod"}, "requires --remote-token"},
		{"client with daemon", config{remote: "https://ember.prod", remoteToken: testToken, daemon: true}, "incompatible with --daemon"},
		{"client with json", config{remote: "https://ember.prod", remoteToken: testToken, jsonMode: true}, "incompatible with --json"},
		{"client with expose", config{remote: "https://ember.prod", remoteToken: testToken, expose: ":9191"}, "incompatible with --expose"},
		{"client with log listener", config{remote: "https://ember.prod", remoteToken: testToken, logListen: ":9210"}, "cannot stream logs"},
		{"instance without remote", config{remoteInstance: "blue"}, "requires --remote"},
		{"token exported for a local TUI", config{remoteToken: "short"}, ""},
		{"weak server token", config{daemon: true, expose: ":9443", remoteToken: "secret"}, "at least 32"},
		{"cert without key", config{expose: ":9443", exposeCert: "c"}, "set together"},
		{"cert without expose", config{exposeCert: "c", exposeKey: "k"}, "requires --expose"},
		{"client CA without cert", config{expose: ":9443", exposeClientCA: "ca"}, "requires --expose-cert"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemote(&tt.cfg)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestExposeTLSConfig(t *testing.T) {
	cert, key := writeSelfSignedCert(t)

	tlsCfg, err := exposeTLSConfig(&config{})
	require.NoError(t, err)
	assert.Nil(t, tlsCfg, "no certificate means plain HTTP")

	_, err = exposeTLSConfig(&config{exposeCert: cert, exposeKey: filepath.Join(t.TempDir(), "missing.key")})
	require.Error(t, err, "a bad key must fail at startup, not on the first handshake")

	tlsCfg, err = exposeTLSConfig(&config{exposeCert: cert, exposeKey: key, exposeClientCA: cert})
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg.ClientCAs)
	assert.Equal(t, "RequireAndVerifyClientCert", tlsCfg.ClientAuth.String())
}

// TestRemoteRoundTrip runs the daemon side and the client side of a remote
// session together, over TLS: the client reads the snapshot, /metrics keeps
// working next to the API, and the session leaves an audit trail.
func TestRemoteRoundTrip(t *testing.T) {
	cert, key := writeSelfSignedCert(t)
	logs := &lockedBuffer{}
	cfg := &config{
		expose:      "127.0.0.1:0",
		interval:    time.Second,
		remoteToken: testToken,
		exposeCert:  cert,
		exposeKey:   key,
		logger:      slog.New(slog.NewTextHandler(logs, nil)),
	}
	holder := &exporter.StateHolder{}
	holder.StoreAll(model.State{Current: &fetcher.Snapshot{
		FetchedAt: time.Now(),
		Metrics:   fetcher.MetricsSnapshot{HTTPRequestsTotal: 7, HasHTTPMetrics: true},
	}}, nil)

	srv, err := newExposeServer(cfg, holder, map[string]time.Duration{"": time.Second}, nil)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	base := "https://" + ln.Addr().String()

	tlsCfg, err := fetcher.BuildTLSConfig(fetcher.TLSOptions{CACert: cert})
	require.NoError(t, err)

	rf, err := fetcher.NewRemoteFetcher(base, testToken, "", tlsCfg)
	require.NoError(t, err)
	snap, err := rf.Fetch(context.Background())
	require.NoError(t, err)
	require.NotNil(t, snap)
	assert.InDelta(t, 7.0, snap.Metrics.HTTPRequestsTotal, 0)

	intruder, err := fetcher.NewRemoteFetcher(base, strings.Repeat("x", 32), "", tlsCfg)
	require.NoError(t, err)
	_, err = intruder.Fetch(context.Background())
	require.Error(t, err)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := client.Get(base + "/metrics")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the remote API must not hide the Prometheus endpoint")

	rf.CloseIdleConnections()
	intruder.CloseIdleConnections()
	client.CloseIdleConnections()
	stopMetricsServer(srv)

	// The server sees the close on its own goroutine, after Shutdown returns.
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "remote session closed") },
		time.Second, 10*time.Millisecond)
	out := logs.String()
	assert.Contains(t, out, "remote session opened")
	assert.Contains(t, out, "remote access denied")
	assert.Equal(t, 1, strings.Count(out, "remote session opened"),
		"neither the rejected client nor the /metrics scrape is a remote session")
	assert.NotContains(t, out, testToken)
}

// lockedBuffer collects log lines written by the server goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// writeSelfSignedCert writes a certificate valid for 127.0.0.1, usable both
// as the server certificate and as the CA that trusts it.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ember-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func TestExposeServer_RemoteAPIOnlyWithToken(t *testing.T) {
	holder := &exporter.StateHolder{}
	holder.StoreAll(model.State{Current: &fetcher.Snapshot{FetchedAt: time.Now()}}, nil)
	cfg := &config{expose: ":0", interval: time.Second, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	srv, err := newExposeServer(cfg, holder, nil, nil)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fetcher.RemoteSnapshotPath, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	srv.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "without --remote-token the route must not exist")
}

// TestExposeServer_TokenAndBasicAuthStayApart pins the mux layering: the token
// opens the remote API only, and --metrics-auth keeps guarding /metrics.
func TestExposeServer_TokenAndBasicAuthStayApart(t *testing.T) {
	holder := &exporter.StateHolder{}
	holder.StoreAll(model.State{Current: &fetcher.Snapshot{FetchedAt: time.Now()}}, nil)
	cfg := &config{
		expose:      ":0",
		interval:    time.Second,
		remoteToken: testToken,
		metricsAuth: "prom:secret",
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv, err := newExposeServer(cfg, holder, nil, nil)
	require.NoError(t, err)

	do := func(path string, auth func(*http.Request)) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		auth(req)
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testToken) }
	basic := func(r *http.Request) { r.SetBasicAuth("prom", "secret") }

	assert.Equal(t, http.StatusOK, do(fetcher.RemoteSnapshotPath, bearer))
	assert.Equal(t, http.StatusUnauthorized, do(fetcher.RemoteSnapshotPath, basic), "Prometheus credentials must not open the remote API")
	assert.Equal(t, http.StatusUnauthorized, do("/metrics", bearer), "the remote token must not open /metrics")
	assert.Equal(t, http.StatusOK, do("/metrics", basic))
}
