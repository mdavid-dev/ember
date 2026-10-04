package ui

import (
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/stretchr/testify/assert"
)

func remoteApp(t *testing.T, remote string, opts ...func(*Config)) *App {
	t.Helper()
	cfg := Config{Interval: time.Second, Remote: remote, HasFrankenPHP: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	app := NewApp(noOpFetcher{}, cfg)
	app.width, app.height = 140, 40
	_, _ = app.Update(fetchMsg{snap: &fetcher.Snapshot{
		FetchedAt:     time.Now(),
		HasFrankenPHP: true,
		Metrics:       fetcher.MetricsSnapshot{HasHTTPMetrics: true},
	}})
	return app
}

func TestRemote_HeaderBadge(t *testing.T) {
	assert.Contains(t, stripANSI(remoteApp(t, "prod:9191").View()), "REMOTE prod:9191")
	assert.NotContains(t, stripANSI(remoteApp(t, "").View()), "REMOTE")
}
