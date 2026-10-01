package app

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
)

func exposeTLSConfig(cfg *config) (*tls.Config, error) {
	if cfg.exposeCert == "" {
		return nil, nil
	}
	tc, err := fetcher.BuildTLSConfig(fetcher.TLSOptions{CACert: cfg.exposeCA, ClientCert: cfg.exposeCert, ClientKey: cfg.exposeKey})
	if err != nil {
		return nil, fmt.Errorf("--expose TLS: %w", err)
	}
	if tc.RootCAs != nil {
		tc.ClientCAs, tc.RootCAs = tc.RootCAs, nil
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

func configureExposeServer(srv *http.Server, cfg *config) error {
	tc, err := exposeTLSConfig(cfg)
	if err != nil {
		return err
	}
	srv.TLSConfig = tc
	if tc != nil {
		srv.ErrorLog = slog.NewLogLogger(cfg.logger.Handler(), slog.LevelWarn)
	}
	if cfg.serveRemote {
		if tc == nil {
			cfg.logger.Warn("--serve-remote without --expose-cert: Caddy's data and the credentials travel in clear text unless a TLS proxy terminates in front of Ember")
		}
		srv.Handler = traceRemote(srv.Handler, cfg.logger)
	}
	return nil
}

func listenMetrics(srv *http.Server) error {
	if srv.TLSConfig != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

func traceRemote(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayed := strings.HasPrefix(r.URL.Path, "/caddy/")
		if r.URL.Path != "/logs" && r.URL.Path != "/certificates" && !relayed {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Caddy's own 4xx answer a TUI read, e.g. a 400 for a config path it lacks.
		daemonRefused := !relayed || rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden || rec.status == http.StatusMethodNotAllowed
		if rec.status >= http.StatusBadRequest && rec.status < http.StatusInternalServerError && daemonRefused {
			log.Warn("remote request refused", "remote_addr", r.RemoteAddr, "method", r.Method, "path", r.URL.Path, "status", rec.status)
		}
		// A TUI opens its session with its first /logs request, served or not.
		if r.URL.Path == "/logs" && r.URL.Query().Get("after") == "-1" && rec.status != http.StatusUnauthorized && rec.status != http.StatusForbidden {
			attrs := []any{"remote_addr", r.RemoteAddr, "user_agent", r.UserAgent()}
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				attrs = append(attrs, "client_cn", r.TLS.PeerCertificates[0].Subject.CommonName)
			}
			log.Info("remote session opened", attrs...)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

const remoteLogsLease = 30 * time.Second

// remoteLogs receives Caddy's logs only while a remote TUI polls /logs, as a
// local TUI does for its session.
type remoteLogs struct {
	hf    *fetcher.HTTPFetcher
	addr  string
	lease time.Duration
	log   *slog.Logger

	mu          sync.Mutex
	unavailable error
	buf         *model.LogBuffer
	stop        func()
	last        time.Time
}

func newRemoteLogs(cfg *config, hf *fetcher.HTTPFetcher) *remoteLogs {
	l := &remoteLogs{lease: remoteLogsLease, log: cfg.logger}
	if addr, ok := logListenAddr(cfg); ok {
		l.hf, l.addr, l.buf = hf, addr, model.NewLogBuffer(0)
	} else {
		l.unavailable = errors.New("logs are not available: Caddy is on another host and the daemon has no --log-listen")
	}
	return l
}

// Since gives a first request (after < 0) the session from its start if it
// opens it, from now otherwise.
func (l *remoteLogs) Since(after int64, limit int) ([]fetcher.LogEntry, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.unavailable != nil {
		return nil, 0, l.unavailable
	}
	if l.stop == nil {
		addr, stop, ok := receiveCaddyLogs(l.addr, l.hf, func(batch []fetcher.LogEntry) {
			for _, e := range batch {
				l.buf.Append(e)
			}
		})
		if !ok {
			return nil, 0, fmt.Errorf("logs are not available: cannot listen on %s", l.addr)
		}
		l.stop = stop
		time.AfterFunc(l.lease, l.expire)
		l.log.Info("remote logs started: log sinks installed in Caddy", "listen", addr)
	} else if after < 0 {
		after = l.buf.WriteCount()
	}
	l.last = time.Now()
	entries, next := l.buf.Since(after, limit)
	return entries, next, nil
}

func (l *remoteLogs) expire() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stop == nil {
		return
	}
	if left := l.lease - time.Since(l.last); left > 0 {
		time.AfterFunc(left, l.expire)
		return
	}
	l.end()
}

func (l *remoteLogs) end() {
	l.stop()
	l.stop = nil
	l.buf.Clear()
	l.log.Info("remote logs stopped: Caddy restored")
}

func (l *remoteLogs) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stop != nil {
		l.end()
	}
	l.unavailable = errors.New("logs are not available: the daemon is stopping")
}
