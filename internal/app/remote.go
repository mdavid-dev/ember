package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/spf13/cobra"
)

func prepareRemote(cmd *cobra.Command, cfg *config) error {
	for _, c := range []struct {
		flag string
		on   bool
	}{
		{"--daemon", cfg.daemon}, {"--json", cfg.jsonMode}, {"--expose", cfg.expose != ""},
		{"--stdin-logs", cfg.stdinLogs}, {"--log-listen", cfg.logListen != ""}, {"--once", cfg.once},
		{"--metrics-auth", cfg.metricsAuth != ""}, {"--serve-remote", cfg.serveRemote}, {"--expose-cert", cfg.exposeCert != ""},
		{"--expose-key", cfg.exposeKey != ""}, {"--expose-client-ca", cfg.exposeCA != ""},
	} {
		if c.on {
			return fmt.Errorf("--remote is incompatible with %s", c.flag)
		}
	}
	u, err := url.Parse(cfg.remote)
	// Before the messages below, which quote the URL.
	if err == nil && u.User != nil {
		return errors.New("--remote must not carry credentials: pass them with EMBER_REMOTE_AUTH or --remote-auth")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" {
		return fmt.Errorf("--remote must be an https:// URL without a query (got %q)", cfg.remote)
	}
	if u.Scheme == "http" && !fetcher.IsLocalAddr(cfg.remote) {
		return fmt.Errorf("--remote must use https://, http:// is only accepted for localhost (got %q)", cfg.remote)
	}
	if cfg.remoteAuth != "" {
		if user, pass, ok := strings.Cut(cfg.remoteAuth, ":"); !ok || user == "" || pass == "" {
			return fmt.Errorf("--remote-auth must be in user:password format (both parts required)")
		}
	}
	if cfg.interval < minInterval {
		return fmt.Errorf("--interval must be at least %s", minInterval)
	}
	if cmd.Flag("addr").Changed {
		cfg.logger.Warn("--addr and EMBER_ADDR are ignored with --remote")
	}
	cfg.remoteURL = u
	return nil
}

func runRemote(ctx context.Context, cfg *config, version string) error {
	f := fetcher.NewRemoteFetcher(cfg.remoteURL, cfg.remoteAuth, version)
	if err := configureTLS(f.HTTPFetcher, effectiveTLS(addrSpec{}, cfg)); err != nil {
		return err
	}
	defer f.CloseIdleConnections()
	// The first /logs request opens the session before the TUI does.
	cfg.remotePage, cfg.logsRefusal = f.FetchLogs(ctx, -1)
	if remoteFatal(cfg.logsRefusal) {
		return fmt.Errorf("remote daemon %s: %w", cfg.remoteURL.Host, cfg.logsRefusal)
	}

	hasFrankenPHP := f.DetectFrankenPHP(ctx)
	f.FetchServerNames(ctx)
	return runTUI(f, cfg, cfg.interval, hasFrankenPHP, version, nil)
}

// remoteFatal stops a remote TUI on an unreachable or failing daemon, on
// refused credentials (401), or on a server without remote sessions (404); any
// other 4xx, such as logs the daemon cannot serve (409), does not stop it.
func remoteFatal(err error) bool {
	var refused fetcher.RefusedError
	return err != nil && (!errors.As(err, &refused) || refused.Status == http.StatusUnauthorized || refused.Status == http.StatusNotFound)
}
