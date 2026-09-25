package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/remote"
	"github.com/alexandre-daubois/ember/internal/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Every remote-mode option lives in this file, so the surface can change in
// one place.
type remoteConfig struct {
	version string

	url        string
	tokenFile  string
	ca         string
	clientCert string
	clientKey  string
	instance   string

	listen            string
	cert              string
	key               string
	clientCA          string
	authFile          string
	maxSessions       int
	insecurePlaintext bool
}

func (rc *remoteConfig) client() bool { return rc.url != "" }
func (rc *remoteConfig) server() bool { return rc.listen != "" }

func addRemoteFlags(f *pflag.FlagSet, rc *remoteConfig) {
	f.StringVar(&rc.url, "remote", "", "Run the TUI against a remote Ember daemon (https://host:port) instead of a Caddy admin API")
	f.StringVar(&rc.tokenFile, "remote-token-file", "", "File holding the remote token (or set EMBER_REMOTE_TOKEN)")
	f.StringVar(&rc.ca, "remote-ca", "", "CA certificate of the remote daemon (default: system roots)")
	f.StringVar(&rc.clientCert, "remote-client-cert", "", "Client certificate for a remote daemon that requires mTLS")
	f.StringVar(&rc.clientKey, "remote-client-key", "", "Client private key for a remote daemon that requires mTLS")
	f.StringVar(&rc.instance, "remote-instance", "", "Instance to show on a multi-instance remote daemon")

	f.StringVar(&rc.listen, "remote-listen", "", "Serve the read-only remote API on this address (requires --daemon)")
	f.StringVar(&rc.cert, "remote-cert", "", "TLS certificate of the remote API listener")
	f.StringVar(&rc.key, "remote-key", "", "TLS private key of the remote API listener")
	f.StringVar(&rc.clientCA, "remote-client-ca", "", "Require client certificates signed by this CA on the remote API (mTLS)")
	f.StringVar(&rc.authFile, "remote-auth", "", "TOML file of the identities and scopes allowed on the remote API")
	f.IntVar(&rc.maxSessions, "remote-max-sessions", 16, "Maximum simultaneous remote sessions")
	f.BoolVar(&rc.insecurePlaintext, "remote-insecure-plaintext", false, "Serve the remote API over plain HTTP, for a TLS-terminating proxy in front of it")
}

// EMBER_REMOTE_TOKEN is read directly, in remote mode only: no flag carries a token.
var (
	remoteClientEnv = map[string]string{"remote": "EMBER_REMOTE", "remote-instance": "EMBER_REMOTE_INSTANCE"}
	remoteServerEnv = map[string]string{
		"remote-listen":    "EMBER_REMOTE_LISTEN",
		"remote-cert":      "EMBER_REMOTE_CERT",
		"remote-key":       "EMBER_REMOTE_KEY",
		"remote-client-ca": "EMBER_REMOTE_CLIENT_CA",
		"remote-auth":      "EMBER_REMOTE_AUTH",
	}
)

// bindRemoteEnv applies the remote variables that fit the mode. A variable
// exported for another mode is ignored with a warning, never an error: an
// exported EMBER_REMOTE must not break a local command.
func bindRemoteEnv(cmd *cobra.Command, cfg *config) error {
	if cmd != cmd.Root() {
		return nil
	}
	cfg.remote.version = cmd.Root().Version
	apply := func(vars map[string]string, applies bool, mode string) error {
		for name, env := range vars {
			f := cmd.Flag(name)
			val := strings.TrimSpace(os.Getenv(env))
			if f == nil || f.Changed || val == "" {
				continue
			}
			if !applies {
				cfg.logger.Warn(env+" is ignored: it only applies to "+mode, "env", env)
				continue
			}
			if err := f.Value.Set(val); err != nil {
				return fmt.Errorf("%s=%q: %w", env, val, err)
			}
			f.Changed = true
		}
		return nil
	}
	if err := apply(remoteClientEnv, !cfg.daemon && !cfg.jsonMode, "the TUI (ember --remote)"); err != nil {
		return err
	}
	return apply(remoteServerEnv, cfg.daemon, "--daemon")
}

// validateRemote runs before validate: in remote mode the Caddy address is
// not used, so a malformed EMBER_ADDR must not stop the TUI.
func validateRemote(cmd *cobra.Command, cfg *config) error {
	rc := &cfg.remote
	changed := func(name string) bool { f := cmd.Flag(name); return f != nil && f.Changed }

	if rc.client() {
		for _, c := range []struct {
			flag string
			set  bool
		}{
			{"--daemon", cfg.daemon}, {"--json", cfg.jsonMode}, {"--expose", cfg.expose != ""},
			{"--stdin-logs", cfg.stdinLogs}, {"--log-listen", cfg.logListen != ""}, {"--remote-listen", rc.server()},
		} {
			if c.set {
				return fmt.Errorf("--remote is incompatible with %s", c.flag)
			}
		}
		if (rc.clientCert == "") != (rc.clientKey == "") {
			return errors.New("--remote-client-cert and --remote-client-key must be set together")
		}
		for _, name := range []string{"addr", "ca-cert", "client-cert", "client-key", "insecure", "interval", "frankenphp-pid"} {
			if changed(name) {
				cfg.logger.Warn("--" + name + " is ignored with --remote: the daemon's own settings apply")
			}
		}
		cfg.addrsRaw = []string{"http://localhost:2019"}
		return nil
	}
	for _, name := range []string{"remote-token-file", "remote-ca", "remote-client-cert", "remote-client-key", "remote-instance"} {
		if changed(name) {
			return fmt.Errorf("--%s requires --remote", name)
		}
	}

	if !rc.server() {
		for _, name := range []string{"remote-cert", "remote-key", "remote-client-ca", "remote-auth", "remote-max-sessions", "remote-insecure-plaintext"} {
			if changed(name) {
				return fmt.Errorf("--%s requires --remote-listen", name)
			}
		}
		return nil
	}
	switch {
	case !cfg.daemon:
		return errors.New("--remote-listen requires --daemon")
	case rc.authFile == "":
		return errors.New("--remote-listen requires --remote-auth (the identities allowed to connect)")
	case rc.insecurePlaintext && (rc.cert != "" || rc.key != "" || rc.clientCA != ""):
		return errors.New("--remote-insecure-plaintext cannot be combined with --remote-cert, --remote-key or --remote-client-ca")
	case !rc.insecurePlaintext && (rc.cert == "" || rc.key == ""):
		return errors.New("--remote-listen requires --remote-cert and --remote-key (or --remote-insecure-plaintext behind a TLS proxy)")
	case rc.maxSessions < 1:
		return errors.New("--remote-max-sessions must be at least 1")
	case rc.listen == cfg.expose:
		return errors.New("--remote-listen must differ from --expose: the remote API has its own listener")
	}
	return nil
}

func readRemoteToken(rc *remoteConfig) (string, error) {
	if rc.tokenFile == "" {
		return strings.TrimSpace(os.Getenv("EMBER_REMOTE_TOKEN")), nil
	}
	data, err := os.ReadFile(rc.tokenFile)
	if err != nil {
		return "", fmt.Errorf("--remote-token-file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func runRemoteTUI(ctx context.Context, cfg *config) error {
	rc := &cfg.remote
	token, err := readRemoteToken(rc)
	if err != nil {
		return err
	}
	tlsCfg, err := fetcher.BuildTLSConfig(fetcher.TLSOptions{CACert: rc.ca, ClientCert: rc.clientCert, ClientKey: rc.clientKey})
	if err != nil {
		return fmt.Errorf("--remote TLS: %w", err)
	}
	sess, err := remote.Connect(ctx, remote.ClientOptions{
		URL: rc.url, Token: token, TLS: tlsCfg, Instance: rc.instance, UserAgent: "ember/" + rc.version,
	})
	if err != nil {
		return err
	}
	defer sess.Close()

	cfg.tuiRemote = &ui.RemoteInfo{Badge: sess.Badge(), Connected: sess.Connected, Unavailable: sess.Unavailable()}
	inst := sess.Instance()
	interval := time.Duration(inst.Interval)
	if interval < minInterval {
		interval = cfg.interval
	}
	return runTUI(sess.Fetcher(), cfg, interval, inst.HasFrankenPHP, rc.version, nil)
}

// startRemoteServer serves the remote API when --remote-listen is set, and
// hooks the instances' polls to it. The returned stop closes the streams
// first, as http.Server.Shutdown waits for them.
func startRemoteServer(instances []*instance, cfg *config, fail context.CancelCauseFunc) (func(), error) {
	rc := &cfg.remote
	if !rc.server() {
		return func() {}, nil
	}
	ids, err := remote.LoadAuthFile(rc.authFile)
	if err != nil {
		return nil, err
	}
	if ids.HasClientCerts() && rc.clientCA == "" {
		return nil, fmt.Errorf("%s declares [[client_cert]] identities, which need --remote-client-ca", rc.authFile)
	}
	tlsCfg, err := remoteServerTLS(rc)
	if err != nil {
		return nil, err
	}

	log := cfg.logger
	specs := make([]remote.InstanceSpec, len(instances))
	for i, inst := range instances {
		specs[i] = remote.InstanceSpec{Name: wireName(inst, instances), Interval: inst.interval}
	}
	b := remote.NewBroadcaster(specs, log)
	for i, inst := range instances {
		inst.remote, inst.remoteName = b, specs[i].Name
	}
	audit := remote.NewAuditor(log)
	srv := &http.Server{
		Handler: remote.NewServer(remote.ServerConfig{
			Auth:         remote.NewAuthenticator(ids, remote.NewRateLimiter(nil), audit, nil),
			Audit:        audit,
			Broadcaster:  b,
			EmberVersion: rc.version,
			MaxSessions:  rc.maxSessions,
		}),
		ReadHeaderTimeout: metricsReadHeaderTimeout,
		TLSConfig:         tlsCfg,
	}
	ln, err := net.Listen("tcp", rc.listen)
	if err != nil {
		return nil, fmt.Errorf("--remote-listen: %w", err)
	}
	go func() {
		var err error
		if tlsCfg != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fail(fmt.Errorf("remote API on %s: %w", rc.listen, err))
		}
	}()

	if rc.insecurePlaintext {
		log.Warn("remote API served over plain HTTP (--remote-insecure-plaintext): tokens and metrics travel in clear unless a TLS proxy terminates in front of it", "addr", ln.Addr().String())
	}
	log.Info("remote API listening", "addr", ln.Addr().String(), "tls", tlsCfg != nil, "mtls", rc.clientCA != "")
	return func() {
		b.Close()
		stopMetricsServer(srv)
	}, nil
}

func remoteServerTLS(rc *remoteConfig) (*tls.Config, error) {
	if rc.insecurePlaintext {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(rc.cert, rc.key)
	if err != nil {
		return nil, fmt.Errorf("--remote-cert/--remote-key: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if rc.clientCA != "" {
		pem, err := os.ReadFile(rc.clientCA)
		if err != nil {
			return nil, fmt.Errorf("--remote-client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--remote-client-ca %s: no PEM certificate found", rc.clientCA)
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// wireName maps the single instance's internal empty name to remote.DefaultInstance.
func wireName(inst *instance, all []*instance) string {
	if len(all) == 1 {
		return remote.DefaultInstance
	}
	return inst.name
}

func (inst *instance) publishSnapshot(snap *fetcher.Snapshot) {
	if inst.remote != nil {
		inst.remote.PublishSnapshot(inst.remoteName, snap)
	}
}

func (inst *instance) publishFailure(err error) {
	if inst.remote != nil {
		inst.remote.PublishFailure(inst.remoteName, err)
	}
}
