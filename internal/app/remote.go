package app

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/spf13/cobra"
)

const remoteHandshakeTimeout = 10 * time.Second

// prepareRemote checks the options of a --remote session.
func prepareRemote(cmd *cobra.Command, cfg *config) error {
	for _, c := range []struct {
		flag string
		on   bool
	}{
		{"--daemon", cfg.daemon}, {"--json", cfg.jsonMode}, {"--expose", cfg.expose != ""},
		{"--stdin-logs", cfg.stdinLogs}, {"--log-listen", cfg.logListen != ""},
	} {
		if c.on {
			return fmt.Errorf("--remote is incompatible with %s", c.flag)
		}
	}
	u, err := url.Parse(cfg.remote)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--remote must be an https:// URL, got %q", cfg.remote)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("--remote must use https:// (http:// is only accepted for localhost), got %q", cfg.remote)
	}
	if cfg.remoteAuth != "" {
		if user, pass, ok := strings.Cut(cfg.remoteAuth, ":"); !ok || user == "" || pass == "" {
			return fmt.Errorf("--remote-auth must be in user:password format (both parts required)")
		}
	}
	if cmd.Flag("addr").Changed {
		cfg.logger.Warn("--addr and EMBER_ADDR are ignored with --remote")
	}
	cfg.remoteURL = u
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runRemote(ctx context.Context, cfg *config, version string) error {
	tlsCfg, err := fetcher.BuildTLSConfig(fetcher.TLSOptions{
		CACert: cfg.caCert, ClientCert: cfg.clientCert, ClientKey: cfg.clientKey, Insecure: cfg.insecure,
	})
	if err != nil {
		return err
	}
	f := fetcher.NewRemoteFetcher(cfg.remoteURL, cfg.remoteAuth, tlsCfg, version)
	defer f.CloseIdleConnections()

	ictx, cancel := context.WithTimeout(ctx, remoteHandshakeTimeout)
	interval, err := f.Interval(ictx)
	cancel()
	if err != nil {
		return fmt.Errorf("remote daemon %s: %w", cfg.remoteURL.Host, err)
	}
	return runTUI(f, cfg, interval, false, version, nil)
}
