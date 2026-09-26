package ui

import (
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	tea "github.com/charmbracelet/bubbletea"
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
		tabLogs:   "Logs are not available in a remote session.",
		tabConfig: "Caddy Config is not available in a remote session.",
	} {
		app := remoteApp(t, "prod:9191")
		app.switchTab(tb)

		out := stripANSI(app.View())

		assert.Contains(t, out, want)
		assert.NotContains(t, out, "--log-listen")
		assert.Nil(t, app.switchTabCmd(), "nothing to fetch from a remote session")
	}
}

func TestRemote_LogsTabShowsTheDaemonLogs(t *testing.T) {
	app := remoteApp(t, "prod:9191", func(c *Config) {
		c.LogBuffer, c.RuntimeLogBuffer, c.RouteAggregator = model.NewLogBuffer(0), model.NewLogBuffer(0), model.NewRouteAggregator()
	})
	app.runtimeLogBuffer.Append(fetcher.LogEntry{Timestamp: time.Now(), Level: "info", Logger: "admin.api", Message: "remote-probe"})
	app.switchTab(tabLogs)

	out := stripANSI(app.View())

	assert.NotContains(t, out, "not available")
	assert.Contains(t, out, "remote-probe")
}

func TestRemote_LogsTabNamesTheRefusal(t *testing.T) {
	app := remoteApp(t, "prod:9191", func(c *Config) {
		c.LogsRefusal = "daemon answered 404 Not Found: logs are not available on a multi-instance daemon\a"
	})
	app.switchTab(tabLogs)

	out := app.View()

	assert.Contains(t, stripANSI(out), "Logs are not available in a remote session.")
	assert.Contains(t, stripANSI(out), "logs are not available on a multi-instance daemon")
	assert.NotContains(t, out, "\a", "the daemon's reason is neutralised")
}

func TestRemote_CertificatesTabFetchesFromTheDaemon(t *testing.T) {
	app := remoteApp(t, "prod:9191")
	app.switchTab(tabCertificates)

	assert.NotNil(t, app.switchTabCmd())
	assert.NotContains(t, stripANSI(app.View()), "not available")
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
