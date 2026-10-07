//go:build integration

package app

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Caddy checks the Host header of its admin API on localhost: only a real
// Caddy tells whether the relay presents one it accepts.
func TestIntegration_RemoteRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	direct := fetcher.NewHTTPFetcher(caddyAddr(), 0)
	before, err := direct.FetchConfig(ctx)
	require.NoError(t, err)

	cfg := &config{interval: time.Second, serveRemote: true, metricsAuth: "remote:s3cret",
		logger: slog.New(slog.DiscardHandler), logSource: &recordingLogSource{buf: model.NewLogBuffer(0)}, relayed: direct}
	daemon := httptest.NewServer(traceRemote(newMetricsHandler(freshHolder(), cfg, nil), cfg.logger))
	t.Cleanup(daemon.Close)
	u, err := url.Parse(daemon.URL)
	require.NoError(t, err)
	remote := fetcher.NewRemoteFetcher(u, "remote:s3cret", "test")
	t.Cleanup(remote.CloseIdleConnections)

	for range 20 {
		resp, err := http.Get("http://localhost:8080/")
		if err == nil {
			resp.Body.Close()
		}
	}
	remote.FetchServerNames(ctx)
	var state model.State
	for range 2 {
		snap, err := remote.Fetch(ctx)
		require.NoError(t, err)
		state.Update(snap)
		time.Sleep(300 * time.Millisecond)
	}
	assert.NotEmpty(t, state.HostDerived, "Caddy's metrics come through the relay")

	relayed, err := remote.FetchConfig(ctx)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(relayed), "the Caddy Config tab shows what an SSH session shows")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, daemon.URL+"/caddy/load", nil)
	require.NoError(t, err)
	req.SetBasicAuth("remote", "s3cret")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	after, err := direct.FetchConfig(ctx)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after), "a remote session leaves Caddy's config as it was")
}
