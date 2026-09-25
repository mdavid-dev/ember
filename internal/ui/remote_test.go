package ui

import (
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func remoteApp(t *testing.T, remote string) *App {
	t.Helper()
	app := NewApp(noOpFetcher{}, Config{Interval: time.Second, Remote: remote, HasFrankenPHP: true})
	app.width, app.height = 140, 40
	_, _ = app.Update(fetchMsg{snap: &fetcher.Snapshot{
		FetchedAt:     time.Now(),
		HasFrankenPHP: true,
		Metrics:       fetcher.MetricsSnapshot{HasHTTPMetrics: true},
	}})
	return app
}

func pressR(app *App) {
	_, _ = app.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
}

func TestRemote_HeaderBadge(t *testing.T) {
	assert.Contains(t, stripANSI(remoteApp(t, "prod:9191").View()), "REMOTE prod:9191")
	assert.NotContains(t, stripANSI(remoteApp(t, "").View()), "REMOTE")
}

func TestRemote_RestartKeySkipsTheConfirmation(t *testing.T) {
	for _, mode := range []viewMode{viewList, viewDetail} {
		app := remoteApp(t, "prod:9191")
		app.switchTab(tabFrankenPHP)
		app.mode = mode

		pressR(app)

		assert.Equal(t, mode, app.mode)
		assert.Equal(t, "Worker restart is not available in a remote session.", app.status)
	}
}

func TestRemote_UnavailableTabs(t *testing.T) {
	for tb, want := range map[tab]string{
		tabLogs:         "Logs are not available in a remote session.",
		tabConfig:       "Caddy Config is not available in a remote session.",
		tabCertificates: "Certificates are not available in a remote session.",
	} {
		app := remoteApp(t, "prod:9191")
		app.switchTab(tb)

		out := stripANSI(app.View())

		assert.Contains(t, out, want)
		assert.NotContains(t, out, "--log-listen")
		assert.Nil(t, app.switchTabCmd(), "nothing to fetch from a remote session")
	}
}

func TestRemote_UpstreamsDoNotFetchTheConfig(t *testing.T) {
	app := remoteApp(t, "prod:9191")

	_, cmd := app.Update(fetchMsg{snap: &fetcher.Snapshot{
		FetchedAt: time.Now().Add(time.Second),
		Metrics: fetcher.MetricsSnapshot{
			HasHTTPMetrics: true,
			Upstreams:      map[string]*fetcher.UpstreamMetrics{"app:8080": {Address: "app:8080", Healthy: 1}},
		},
	}})

	assert.Nil(t, cmd, "a remote session cannot read the upstream config")
	assert.Empty(t, app.status)
}
