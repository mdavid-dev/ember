package ui

// RemoteInfo marks a TUI reading a remote daemon (ember --remote).
type RemoteInfo struct {
	Badge     string
	Connected func() bool
	// Unavailable maps "logs", "config" and "certificates" to why that tab is empty.
	Unavailable map[string]string
}

const remoteRestartMsg = "Worker restart is not available in a remote session (read-only)."

func (a *App) remoteReason(feature string) string {
	if a.config.Remote == nil {
		return ""
	}
	return a.config.Remote.Unavailable[feature]
}

// askRestart opens the restart confirmation, which a remote session skips.
func (a *App) askRestart() {
	if a.config.Remote != nil {
		a.status = remoteRestartMsg
		return
	}
	a.mode = viewConfirmRestart
}

func renderRemoteBadge(r *RemoteInfo, width int) string {
	label, style := " REMOTE "+sanitizeControl(r.Badge), okStyle
	if r.Connected != nil && !r.Connected() {
		label, style = label+" (disconnected)", dangerStyle
	}
	return style.Inline(true).MaxWidth(width).Render(label)
}
