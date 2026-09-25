package ui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/internal/fetcher"
)

func newRemoteApp(connected bool) *App {
	app := NewApp(noOpFetcher{}, Config{
		Interval:      time.Second,
		HasFrankenPHP: true,
		Remote: &RemoteInfo{
			Badge:     "alice@ember.prod:9443",
			Connected: func() bool { return connected },
			Unavailable: map[string]string{
				"logs":         "Logs unavailable: your token lacks the \"logs\" scope.",
				"config":       "Config unavailable: this daemon does not serve it.",
				"certificates": "Certificates unavailable: this daemon does not serve it.",
			},
		},
	})
	app.width, app.height = 120, 40
	app.state.Update(&fetcher.Snapshot{FetchedAt: time.Now()})
	return app
}

func rune1(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

func TestRemote_BadgeInHeader(t *testing.T) {
	out := stripANSI(newRemoteApp(true).View())
	assert.Contains(t, out, "REMOTE alice@ember.prod:9443")
	assert.NotContains(t, out, "disconnected")

	out = stripANSI(newRemoteApp(false).View())
	assert.Contains(t, out, "REMOTE alice@ember.prod:9443 (disconnected)", "readable without colour too")

	local := NewApp(noOpFetcher{}, Config{Interval: time.Second})
	local.width, local.height = 120, 40
	assert.NotContains(t, stripANSI(local.View()), "REMOTE")
}

func TestRemote_BadgeIsSanitized(t *testing.T) {
	app := newRemoteApp(true)
	app.config.Remote.Badge = "mallory\x1b]0;pwned\x07@host"
	out := app.View()
	assert.NotContains(t, out, "\x1b]0;")
	assert.NotContains(t, out, "\x07")
}

func TestRemote_TabsSayWhyTheyAreEmpty(t *testing.T) {
	for tb, want := range map[tab]string{
		tabLogs:         `Logs unavailable: your token lacks the "logs" scope.`,
		tabConfig:       "Config unavailable: this daemon does not serve it.",
		tabCertificates: "Certificates unavailable: this daemon does not serve it.",
	} {
		app := newRemoteApp(true)
		app.activeTab = tb
		out := stripANSI(app.View())
		assert.Contains(t, out, want)
		assert.NotContains(t, out, "Loading")
		assert.NotContains(t, out, "--log-listen", "the local hint does not apply to a remote session")
	}
}

func TestRemote_NoFetchForUnavailableFeatures(t *testing.T) {
	app := newRemoteApp(true)
	assert.Nil(t, app.doFetchConfig())
	assert.Nil(t, app.doFetchCertificates())
	assert.Nil(t, app.doFetchRPConfig())

	local := NewApp(noOpFetcher{}, Config{Interval: time.Second})
	assert.NotNil(t, local.doFetchConfig())
}

func TestRemote_RestartIsRefusedWithoutConfirmation(t *testing.T) {
	app := newRemoteApp(true)
	app.activeTab = tabFrankenPHP
	app.handleListKey(rune1('r'))
	assert.NotEqual(t, viewConfirmRestart, app.mode)
	assert.Equal(t, remoteRestartMsg, app.status)

	app = newRemoteApp(true)
	app.activeTab = tabFrankenPHP
	app.mode = viewDetail
	app.handleDetailKey(rune1('r'))
	assert.Equal(t, viewDetail, app.mode, "the detail view stays, no confirmation")
	assert.Equal(t, remoteRestartMsg, app.status)
	assert.Contains(t, stripANSI(app.View()), "Worker restart is not available in a remote session (read-only).")
}

func TestRemote_LocalRestartStillAsks(t *testing.T) {
	app := NewApp(noOpFetcher{}, Config{Interval: time.Second, HasFrankenPHP: true})
	app.activeTab = tabFrankenPHP
	app.handleListKey(rune1('r'))
	assert.Equal(t, viewConfirmRestart, app.mode)
}

func TestRemote_HelpMarksRestartUnavailable(t *testing.T) {
	out := stripANSI(renderHelpOverlay(120, 40, true, nil, []tab{tabCaddy}, true))
	assert.Contains(t, out, "Restart workers: unavailable in a remote session (read-only)")

	app := newRemoteApp(true)
	app.mode = viewHelp
	require.Contains(t, stripANSI(app.View()), "unavailable in a remote session")
}
