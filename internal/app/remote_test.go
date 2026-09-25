package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/alexandre-daubois/ember/internal/remote"
)

const remoteTestToken = "ember_rt_dGVzdHRva2VudGVzdHRva2VudGVzdHRva2VudGVzdHQ"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	dir  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ember test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	ca := &testCA{cert: cert, key: key, pool: pool, dir: t.TempDir()}
	ca.write(t, "ca.pem", "CERTIFICATE", der)
	return ca
}

func (ca *testCA) write(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(ca.dir, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
	return path
}

// issue writes a certificate and key signed by the CA and returns their paths.
func (ca *testCA) issue(t *testing.T, name string, client bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if client {
		tmpl.ExtKeyUsage, tmpl.IPAddresses = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return ca.write(t, name+".pem", "CERTIFICATE", der), ca.write(t, name+"-key.pem", "EC PRIVATE KEY", keyDER)
}

func writeAuthFile(t *testing.T, extra string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(remoteTestToken))
	path := filepath.Join(t.TempDir(), "auth.toml")
	content := fmt.Sprintf("[[token]]\nname = \"alice\"\nsha256 = %q\nscopes = [\"snapshot\"]\n%s", hex.EncodeToString(sum[:]), extra)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// fakeCaddy serves a /metrics whose request counter grows on every scrape,
// and records every request it receives.
type fakeCaddy struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	scrapes  atomic.Int64
}

func newFakeCaddy(t *testing.T) *fakeCaddy {
	t.Helper()
	fc := &fakeCaddy{}
	fc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		fc.requests = append(fc.requests, r.Method+" "+r.URL.Path)
		fc.mu.Unlock()
		if r.URL.Path != "/metrics" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := fc.scrapes.Add(1) * 10
		fmt.Fprintf(w, "# TYPE caddy_http_requests_total counter\ncaddy_http_requests_total{server=\"srv0\",host=\"shop.test\"} %d\n", n)
		fmt.Fprintf(w, "# TYPE caddy_http_request_duration_seconds histogram\n"+
			"caddy_http_request_duration_seconds_bucket{server=\"srv0\",host=\"shop.test\",le=\"0.1\"} %d\n"+
			"caddy_http_request_duration_seconds_bucket{server=\"srv0\",host=\"shop.test\",le=\"+Inf\"} %d\n"+
			"caddy_http_request_duration_seconds_sum{server=\"srv0\",host=\"shop.test\"} %d\n"+
			"caddy_http_request_duration_seconds_count{server=\"srv0\",host=\"shop.test\"} %d\n", n, n, n/10, n)
	}))
	t.Cleanup(fc.Close)
	return fc
}

func (fc *fakeCaddy) methods() []string {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var out []string
	for _, r := range fc.requests {
		out = append(out, strings.Fields(r)[0])
	}
	return out
}

type remoteDaemon struct {
	cfg    *config
	ca     *testCA
	listen string
	expose string
	logs   *lockedLog
	done   chan error
	cancel context.CancelFunc
}

type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func startRemoteDaemon(t *testing.T, caddyURL string, configure func(*remoteConfig, *testCA)) *remoteDaemon {
	t.Helper()
	ca := newTestCA(t)
	certPath, keyPath := ca.issue(t, "daemon", false)
	d := &remoteDaemon{ca: ca, listen: freeAddr(t), expose: freeAddr(t), logs: &lockedLog{}, done: make(chan error, 1)}
	d.cfg = &config{
		addrs: []addrSpec{{url: caddyURL}},
		// Rates need 100 ms between snapshots.
		interval: 150 * time.Millisecond,
		expose:   d.expose,
		daemon:   true,
		logger:   slog.New(slog.NewJSONHandler(d.logs, nil)),
		remote: remoteConfig{
			version: "1.7.0-test", listen: d.listen, cert: certPath, key: keyPath,
			authFile: writeAuthFile(t, ""), maxSessions: 16,
		},
	}
	if configure != nil {
		configure(&d.cfg.remote, ca)
	}
	instances, err := newInstances(context.Background(), d.cfg, "v-test")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	go func() { d.done <- runDaemon(ctx, instances, d.cfg, nil) }()
	t.Cleanup(func() { d.stop(t) })
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", d.listen)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 10*time.Second, 10*time.Millisecond)
	return d
}

func (d *remoteDaemon) stop(t *testing.T) {
	t.Helper()
	d.cancel()
	select {
	case err := <-d.done:
		require.NoError(t, err)
		d.done <- nil
	case <-time.After(10 * time.Second):
		require.FailNow(t, "daemon did not stop")
	}
}

func (d *remoteDaemon) connect(t *testing.T, token string, cert tls.Certificate) (*remote.Session, error) {
	t.Helper()
	tlsCfg := &tls.Config{RootCAs: d.ca.pool, MinVersion: tls.VersionTLS12}
	if cert.Certificate != nil {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	s, err := remote.Connect(context.Background(), remote.ClientOptions{
		URL: "https://" + d.listen, Token: token, TLS: tlsCfg, UserAgent: "ember/test",
	})
	if s != nil {
		t.Cleanup(s.Close)
	}
	return s, err
}

func TestRemote_EndToEnd(t *testing.T) {
	caddy := newFakeCaddy(t)
	d := startRemoteDaemon(t, caddy.URL, nil)
	s, err := d.connect(t, remoteTestToken, tls.Certificate{})
	require.NoError(t, err)
	assert.Equal(t, remote.DefaultInstance, s.Instance().Name)
	assert.Equal(t, "alice", s.Info().Identity)
	assert.Equal(t, "1.7.0-test", s.Info().EmberVersion)

	var state model.State
	var sawRPS bool
	for range 4 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		snap, err := s.Fetcher().Fetch(ctx)
		cancel()
		require.NoError(t, err)
		state.Update(snap)
		sawRPS = sawRPS || state.Derived.RPS > 0
	}
	assert.True(t, sawRPS, "rates are computed client-side from consecutive remote snapshots")

	for _, m := range caddy.methods() {
		assert.Equal(t, http.MethodGet, m, "nothing but reads reaches Caddy")
	}

	resp, err := http.Get("http://" + d.expose + remote.RouteInfo)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "the Prometheus listener does not serve the remote API")

	d.stop(t)
	require.Eventually(t, func() bool { return !s.Connected() }, 10*time.Second, 10*time.Millisecond)
	logs := d.logs.String()
	assert.Contains(t, logs, `"msg":"remote.session.open"`)
	assert.Contains(t, logs, `"reason":"shutdown"`)
	assert.NotContains(t, logs, remoteTestToken)
}

func TestRemote_DaemonReportsCaddyOutage(t *testing.T) {
	caddy := newFakeCaddy(t)
	d := startRemoteDaemon(t, caddy.URL, nil)
	s, err := d.connect(t, remoteTestToken, tls.Certificate{})
	require.NoError(t, err)
	caddy.Close()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := s.Fetch(ctx)
		return err != nil && strings.Contains(err.Error(), "the daemon cannot reach Caddy since")
	}, 10*time.Second, 20*time.Millisecond)
}

func TestRemote_MutualTLS(t *testing.T) {
	caddy := newFakeCaddy(t)
	d := startRemoteDaemon(t, caddy.URL, func(rc *remoteConfig, ca *testCA) {
		rc.clientCA = filepath.Join(ca.dir, "ca.pem")
		rc.authFile = writeAuthFile(t, "[[client_cert]]\ncn = \"bob\"\nscopes = [\"snapshot\"]\n")
	})

	_, err := d.connect(t, remoteTestToken, tls.Certificate{})
	require.Error(t, err, "without a client certificate the TLS handshake fails, token or not")

	certPath, keyPath := d.ca.issue(t, "bob", true)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	s, err := d.connect(t, "", cert)
	require.NoError(t, err)
	assert.Equal(t, "bob", s.Info().Identity)
}

func TestStartRemoteServer_StartupErrors(t *testing.T) {
	ca := newTestCA(t)
	certPath, keyPath := ca.issue(t, "daemon", false)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = busy.Close() }()

	for name, tc := range map[string]struct {
		rc   remoteConfig
		want string
	}{
		"missing auth file":      {remoteConfig{listen: "127.0.0.1:0", authFile: "/nonexistent.toml", cert: certPath, key: keyPath}, "remote auth file"},
		"client_cert without CA": {remoteConfig{listen: "127.0.0.1:0", authFile: writeAuthFile(t, "[[client_cert]]\ncn = \"bob\"\nscopes = [\"snapshot\"]\n"), cert: certPath, key: keyPath}, "need --remote-client-ca"},
		"bad certificate":        {remoteConfig{listen: "127.0.0.1:0", authFile: writeAuthFile(t, ""), cert: keyPath, key: keyPath}, "--remote-cert/--remote-key"},
		"bad client CA":          {remoteConfig{listen: "127.0.0.1:0", authFile: writeAuthFile(t, ""), cert: certPath, key: keyPath, clientCA: keyPath}, "no PEM certificate"},
		"missing client CA":      {remoteConfig{listen: "127.0.0.1:0", authFile: writeAuthFile(t, ""), cert: certPath, key: keyPath, clientCA: "/nonexistent.pem"}, "--remote-client-ca"},
		"busy address":           {remoteConfig{listen: busy.Addr().String(), authFile: writeAuthFile(t, ""), cert: certPath, key: keyPath}, "--remote-listen"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config{remote: tc.rc, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			_, err := startRemoteServer(nil, cfg, func(error) {})
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestStartRemoteServer_PlaintextWarns(t *testing.T) {
	var logs bytes.Buffer
	cfg := &config{
		remote: remoteConfig{listen: "127.0.0.1:0", authFile: writeAuthFile(t, ""), insecurePlaintext: true, maxSessions: 1},
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	stop, err := startRemoteServer(nil, cfg, func(error) {})
	require.NoError(t, err)
	stop()
	assert.Contains(t, logs.String(), "tokens and metrics travel in clear")
}

func TestRemote_FlagValidation(t *testing.T) {
	auth := writeAuthFile(t, "")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"remote with daemon":     {[]string{"--remote", "https://x:1", "--daemon", "--expose", ":9191"}, "--remote is incompatible with --daemon"},
		"remote with json":       {[]string{"--remote", "https://x:1", "--json"}, "--remote is incompatible with --json"},
		"remote with expose":     {[]string{"--remote", "https://x:1", "--expose", ":9191"}, "--remote is incompatible with --expose"},
		"remote with log-listen": {[]string{"--remote", "https://x:1", "--log-listen", ":9210"}, "--remote is incompatible with --log-listen"},
		"half client pair":       {[]string{"--remote", "https://x:1", "--remote-client-cert", "c.pem"}, "must be set together"},
		"client flag alone":      {[]string{"--remote-token-file", "t"}, "--remote-token-file requires --remote"},
		"listen without daemon":  {[]string{"--remote-listen", ":9443"}, "--remote-listen requires --daemon"},
		"listen without auth":    {[]string{"--daemon", "--expose", ":9191", "--remote-listen", ":9443"}, "requires --remote-auth"},
		"listen without TLS":     {[]string{"--daemon", "--expose", ":9191", "--remote-listen", ":9443", "--remote-auth", auth}, "requires --remote-cert and --remote-key"},
		"plaintext with cert":    {[]string{"--daemon", "--expose", ":9191", "--remote-listen", ":9443", "--remote-auth", auth, "--remote-insecure-plaintext", "--remote-cert", "c"}, "cannot be combined"},
		"shared with expose":     {[]string{"--daemon", "--expose", ":9191", "--remote-listen", ":9191", "--remote-auth", auth, "--remote-insecure-plaintext"}, "must differ from --expose"},
		"zero sessions":          {[]string{"--daemon", "--expose", ":9191", "--remote-listen", ":9443", "--remote-auth", auth, "--remote-insecure-plaintext", "--remote-max-sessions", "0"}, "at least 1"},
		"server flag alone":      {[]string{"--remote-auth", auth}, "--remote-auth requires --remote-listen"},
		"plain http to a host":   {[]string{"--remote", "http://ember.example.com:9443"}, "plain http would send the token in clear"},
		"unreachable remote":     {[]string{"--remote", "https://127.0.0.1:1"}, "remote daemon 127.0.0.1:1"},
		"missing token file":     {[]string{"--remote", "https://127.0.0.1:1", "--remote-token-file", "/nonexistent"}, "--remote-token-file"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Run(tc.args, "0.0.0")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// An exported remote variable must never break a command of another mode.
func TestRemote_EnvForAnotherModeIsIgnored(t *testing.T) {
	t.Run("client variables in daemon or json mode", func(t *testing.T) {
		t.Setenv("EMBER_REMOTE", "https://ember.example.com:9443")
		t.Setenv("EMBER_REMOTE_INSTANCE", "web")
		t.Setenv("EMBER_REMOTE_TOKEN", remoteTestToken)
		require.ErrorContains(t, Run([]string{"--daemon"}, "0.0.0"), "--daemon requires --expose")
		err := Run([]string{"--json", "--once", "--addr", "http://127.0.0.1:1", "--timeout", "1s"}, "0.0.0")
		if err != nil {
			assert.NotContains(t, err.Error(), "remote")
		}
	})
	t.Run("server variables outside daemon mode", func(t *testing.T) {
		t.Setenv("EMBER_REMOTE_LISTEN", ":9443")
		t.Setenv("EMBER_REMOTE_AUTH", "/nonexistent.toml")
		require.ErrorContains(t, Run([]string{"--once"}, "0.0.0"), "--once requires --json")
		err := Run([]string{"--json", "--once", "--addr", "http://127.0.0.1:1", "--timeout", "1s"}, "0.0.0")
		if err != nil {
			assert.NotContains(t, err.Error(), "remote")
		}
	})
	t.Run("subcommands", func(t *testing.T) {
		t.Setenv("EMBER_REMOTE", "https://ember.example.com:9443")
		t.Setenv("EMBER_REMOTE_LISTEN", ":9443")
		err := Run([]string{"diff", "/nonexistent-a", "/nonexistent-b"}, "0.0.0")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "remote")
	})
	t.Run("server variables in daemon mode apply", func(t *testing.T) {
		t.Setenv("EMBER_REMOTE_LISTEN", ":9443")
		require.ErrorContains(t, Run([]string{"--daemon", "--expose", ":9191"}, "0.0.0"), "--remote-listen requires --remote-auth")
	})
}

func TestRemote_EnvSelectsRemoteMode(t *testing.T) {
	t.Setenv("EMBER_REMOTE", "https://127.0.0.1:1")
	t.Setenv("EMBER_ADDR", "not a valid address::")
	err := Run(nil, "0.0.0")
	require.ErrorContains(t, err, "remote daemon 127.0.0.1:1", "EMBER_ADDR is ignored, with a warning, in remote mode")
}

func TestReadRemoteToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("  "+remoteTestToken+"\n"), 0o600))
	tok, err := readRemoteToken(&remoteConfig{tokenFile: path})
	require.NoError(t, err)
	assert.Equal(t, remoteTestToken, tok)

	t.Setenv("EMBER_REMOTE_TOKEN", " from-env ")
	tok, err = readRemoteToken(&remoteConfig{})
	require.NoError(t, err)
	assert.Equal(t, "from-env", tok)
}

func TestWireName(t *testing.T) {
	single := []*instance{{name: ""}}
	assert.Equal(t, remote.DefaultInstance, wireName(single[0], single))
	multi := []*instance{{name: "api"}, {name: "web"}}
	assert.Equal(t, "web", wireName(multi[1], multi))

	var inst instance
	inst.publishSnapshot(nil)
	inst.publishFailure(nil)
}
