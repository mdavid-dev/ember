package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alexandre-daubois/ember/internal/exporter"
	"github.com/alexandre-daubois/ember/internal/fetcher"
)

// minRemoteTokenLen rejects tokens short enough to brute-force over the
// network: the endpoint is meant to be reachable from outside the
// infrastructure, and it has no rate limiting of its own.
const minRemoteTokenLen = 32

// runRemote starts the TUI against another Ember process running with
// --daemon --remote-token, instead of a Caddy admin API. Plugins are left out:
// they are provisioned with a Caddy address, which a remote session has none
// of.
func runRemote(cfg *config, version string) error {
	tlsCfg, err := fetcher.BuildTLSConfig(fetcher.TLSOptions{
		CACert:     cfg.caCert,
		ClientCert: cfg.clientCert,
		ClientKey:  cfg.clientKey,
		Insecure:   cfg.insecure,
	})
	if err != nil {
		return err
	}
	rf, err := fetcher.NewRemoteFetcher(cfg.remote, cfg.remoteToken, cfg.remoteInstance, tlsCfg)
	if err != nil {
		return err
	}
	defer rf.CloseIdleConnections()
	return runTUI(rf, cfg, cfg.interval, false, version, nil)
}

// newExposeServer builds the --expose server: the Prometheus endpoints, plus
// the remote TUI API when --remote-token is set, over TLS when --expose-cert
// is set.
//
// api serves the config, certificate and log routes; nil limits the remote
// API to snapshots.
func newExposeServer(cfg *config, holder *exporter.StateHolder, perInstance map[string]time.Duration, api *remoteAPI) (*http.Server, error) {
	handler := newMetricsHandler(holder, cfg, perInstance)

	var audit *remoteAudit
	if cfg.remoteToken != "" {
		audit = &remoteAudit{log: cfg.logger}
		snapshots := exporter.SnapshotHandler(holder, cfg.interval, perInstance)
		mux := http.NewServeMux()
		protect := func(h http.Handler) http.Handler {
			return exporter.BearerAuth(audit.wrap(h), cfg.remoteToken, cfg.logger)
		}
		mux.Handle(fetcher.RemoteSnapshotPath, protect(snapshots))
		if api != nil {
			api.register(mux, protect)
		}
		// Everything else keeps its own --metrics-auth, if any.
		mux.Handle("/", handler)
		handler = mux
	}

	srv := newMetricsServer(cfg.expose, handler)
	if audit != nil {
		srv.ConnContext = audit.connContext
		srv.ConnState = audit.connState
	}

	tlsCfg, err := exposeTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	srv.TLSConfig = tlsCfg

	if cfg.remoteToken != "" && tlsCfg == nil {
		cfg.logger.Warn("remote API served over plain HTTP: the token travels in clear text; set --expose-cert/--expose-key or terminate TLS in front of Ember")
	}
	return srv, nil
}

// serveExpose runs srv until it is shut down, over TLS when its TLSConfig
// carries a certificate.
func serveExpose(srv *http.Server) error {
	if srv.TLSConfig != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

// exposeTLSConfig loads the --expose certificate once, at startup, so a bad
// path or key fails the command instead of the first client handshake. With
// --expose-client-ca, every client must present a certificate signed by that
// CA (mTLS), Prometheus scrapers included.
func exposeTLSConfig(cfg *config) (*tls.Config, error) {
	if cfg.exposeCert == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.exposeCert, cfg.exposeKey)
	if err != nil {
		return nil, fmt.Errorf("load --expose-cert/--expose-key: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if cfg.exposeClientCA != "" {
		pem, err := os.ReadFile(cfg.exposeClientCA)
		if err != nil {
			return nil, fmt.Errorf("read --expose-client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid CA cert in %s", cfg.exposeClientCA)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

func validateRemote(cfg *config) error {
	if cfg.remote != "" {
		switch {
		case cfg.daemon:
			return errors.New("--remote is incompatible with --daemon")
		case cfg.jsonMode:
			return errors.New("--remote is incompatible with --json")
		case cfg.expose != "":
			return errors.New("--remote is incompatible with --expose")
		case cfg.stdinLogs || cfg.logListen != "":
			return errors.New("--remote cannot stream logs; drop --stdin-logs / --log-listen")
		case cfg.remoteToken == "":
			return errors.New("--remote requires --remote-token (or EMBER_REMOTE_TOKEN)")
		}
	}
	if cfg.remoteInstance != "" && cfg.remote == "" {
		return errors.New("--remote-instance requires --remote")
	}
	// Outside --daemon and --remote the token is simply unused: failing would
	// break every local command once EMBER_REMOTE_TOKEN is exported.
	if cfg.remoteToken != "" && cfg.daemon {
		if len(cfg.remoteToken) < minRemoteTokenLen {
			return fmt.Errorf("--remote-token must be at least %d characters (e.g. openssl rand -hex 32)", minRemoteTokenLen)
		}
	}
	if (cfg.exposeCert == "") != (cfg.exposeKey == "") {
		return errors.New("--expose-cert and --expose-key must be set together")
	}
	if cfg.exposeCert != "" && cfg.expose == "" {
		return errors.New("--expose-cert requires --expose")
	}
	if cfg.exposeClientCA != "" && cfg.exposeCert == "" {
		return errors.New("--expose-client-ca requires --expose-cert and --expose-key")
	}
	return nil
}

// remoteAudit logs one line when a remote TUI opens a session and one when it
// closes it. A TUI polls every second over a keep-alive connection, so a line
// per request would drown the log; a line per connection keeps who connected,
// from where and for how long.
type remoteAudit struct {
	log      *slog.Logger
	sessions sync.Map // net.Conn -> *remoteSession
}

type remoteSession struct {
	opened   time.Time
	remote   string
	requests atomic.Int64
	// identity is written by the first request's handler and read when the
	// connection closes; over HTTP/2 those run on different goroutines.
	identity atomic.Pointer[string]
}

func (s *remoteSession) clientCert() string {
	if p := s.identity.Load(); p != nil {
		return *p
	}
	return ""
}

type remoteSessionKey struct{}

func (a *remoteAudit) connContext(ctx context.Context, c net.Conn) context.Context {
	s := &remoteSession{opened: time.Now(), remote: c.RemoteAddr().String()}
	a.sessions.Store(c, s)
	return context.WithValue(ctx, remoteSessionKey{}, s)
}

func (a *remoteAudit) connState(c net.Conn, state http.ConnState) {
	if state != http.StateClosed && state != http.StateHijacked {
		return
	}
	v, ok := a.sessions.LoadAndDelete(c)
	if !ok {
		return
	}
	// Connections that never passed the token check (Prometheus scrapes,
	// rejected attempts) are not remote sessions.
	if s := v.(*remoteSession); s.requests.Load() > 0 {
		a.log.Info("remote session closed",
			"remote_addr", s.remote,
			"client_cert", s.clientCert(),
			"requests", s.requests.Load(),
			"duration", time.Since(s.opened).Truncate(time.Second).String())
	}
}

// wrap counts authenticated requests; it must sit behind the token check.
func (a *remoteAudit) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s, ok := r.Context().Value(remoteSessionKey{}).(*remoteSession); ok && s.requests.Add(1) == 1 {
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				cn := r.TLS.PeerCertificates[0].Subject.CommonName
				s.identity.Store(&cn)
			}
			a.log.Info("remote session opened",
				"remote_addr", s.remote,
				"client_cert", s.clientCert(),
				"instance", r.URL.Query().Get("instance"),
				"user_agent", r.UserAgent())
		}
		next.ServeHTTP(w, r)
	})
}
