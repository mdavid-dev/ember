package ui

import (
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/stretchr/testify/assert"
)

func TestRemote_HeaderBadge(t *testing.T) {
	for remote, want := range map[string]string{"prod:9191": "REMOTE prod:9191", "": ""} {
		app := NewApp(noOpFetcher{}, Config{Interval: time.Second, Remote: remote})
		app.width, app.height = 140, 40
		_, _ = app.Update(fetchMsg{snap: &fetcher.Snapshot{FetchedAt: time.Now(), Metrics: fetcher.MetricsSnapshot{HasHTTPMetrics: true}}})

		out := stripANSI(app.View())

		if want == "" {
			assert.NotContains(t, out, "REMOTE")
		} else {
			assert.Contains(t, out, want)
		}
	}
}
