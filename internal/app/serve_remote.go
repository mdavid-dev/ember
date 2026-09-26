package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/alexandre-daubois/ember/internal/exporter"
)

func exposeTLSConfig(cfg *config) (*tls.Config, error) {
	if cfg.exposeCert == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.exposeCert, cfg.exposeKey)
	if err != nil {
		return nil, fmt.Errorf("load --expose-cert/--expose-key: %w", err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if cfg.exposeCA != "" {
		data, err := os.ReadFile(cfg.exposeCA)
		if err != nil {
			return nil, fmt.Errorf("read --expose-client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("invalid CA cert in %s", cfg.exposeCA)
		}
		tc.ClientCAs = pool
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
			cfg.logger.Warn("--serve-remote without --expose-cert: snapshots and credentials travel in clear text unless a TLS proxy terminates in front of Ember")
		}
		srv.Handler = traceRemote(srv.Handler, cfg.logger)
	}
	return nil
}

// certSources keys each fetcher like the state holder: "" on a single instance.
func certSources(instances []*instance) map[string]exporter.CertSource {
	sources := make(map[string]exporter.CertSource, len(instances))
	for _, inst := range instances {
		key := ""
		if isMulti(instances) {
			key = inst.name
		}
		sources[key] = inst.fetcher
	}
	return sources
}

func listenMetrics(srv *http.Server) error {
	if srv.TLSConfig != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

// traceRemote logs a TUI's first snapshot request, the only one without
// ?after=, and every refused remote request.
func traceRemote(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/snapshot" && r.URL.Path != "/certificates" {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		switch {
		case rec.status >= http.StatusBadRequest && rec.status < http.StatusInternalServerError:
			log.Warn("remote request refused", "remote_addr", r.RemoteAddr, "status", rec.status)
		case rec.status == http.StatusOK && r.URL.Path == "/snapshot" && !r.URL.Query().Has("after"):
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
