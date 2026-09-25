package remote

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// Audit event names. Their keys are stable: alerts rely on them.
const (
	AuditAuthDenied   = "remote.auth.denied"
	AuditSessionOpen  = "remote.session.open"
	AuditSessionClose = "remote.session.close"
	AuditRead         = "remote.read"
)

// DenyReason goes to the audit log only, never to the client.
type DenyReason string

const (
	DenyMissing     DenyReason = "missing"
	DenyInvalid     DenyReason = "invalid"
	DenyExpired     DenyReason = "expired"
	DenyRateLimited DenyReason = "rate_limited"
	DenyCert        DenyReason = "cert"
	DenyScope       DenyReason = "scope"
)

type CloseReason string

const (
	CloseClient     CloseReason = "client"
	CloseShutdown   CloseReason = "shutdown"
	CloseSlowClient CloseReason = "slow_client"
	CloseRevoked    CloseReason = "revoked"
)

// maxAuditFieldLen bounds the client-supplied strings of an audit line.
const maxAuditFieldLen = 256

type Auditor struct {
	log *slog.Logger
}

// NewAuditor discards the events when log is nil.
func NewAuditor(log *slog.Logger) *Auditor {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Auditor{log: log}
}

type AuthDeniedEvent struct {
	RemoteAddr string
	Reason     DenyReason
	UserAgent  string
}

func (a *Auditor) AuthDenied(ctx context.Context, e AuthDeniedEvent) {
	a.emit(ctx, slog.LevelWarn, AuditAuthDenied,
		slog.String("remote_addr", e.RemoteAddr),
		slog.String("reason", string(e.Reason)),
		slog.String("user_agent", clip(e.UserAgent)),
	)
}

type SessionOpenEvent struct {
	SessionID    string
	Identity     string
	ClientCN     string
	RemoteAddr   string
	Instance     string
	Scopes       []string
	UserAgent    string
	EmberVersion string
}

func (a *Auditor) SessionOpen(ctx context.Context, e SessionOpenEvent) {
	a.emit(ctx, slog.LevelInfo, AuditSessionOpen,
		slog.String("session_id", e.SessionID),
		slog.String("identity", e.Identity),
		slog.String("client_cn", e.ClientCN),
		slog.String("remote_addr", e.RemoteAddr),
		slog.String("instance", e.Instance),
		slog.Any("scopes", e.Scopes),
		slog.String("user_agent", clip(e.UserAgent)),
		slog.String("ember_version", clip(e.EmberVersion)),
	)
}

type SessionCloseEvent struct {
	SessionID string
	Identity  string
	Duration  time.Duration
	Events    int64
	Bytes     int64
	Reason    CloseReason
}

func (a *Auditor) SessionClose(ctx context.Context, e SessionCloseEvent) {
	a.emit(ctx, slog.LevelInfo, AuditSessionClose,
		slog.String("session_id", e.SessionID),
		slog.String("identity", e.Identity),
		slog.Duration("duration", e.Duration),
		slog.Int64("events", e.Events),
		slog.Int64("bytes", e.Bytes),
		slog.String("reason", string(e.Reason)),
	)
}

type ReadEvent struct {
	SessionID string
	Identity  string
	Resource  string
}

func (a *Auditor) Read(ctx context.Context, e ReadEvent) {
	a.emit(ctx, slog.LevelInfo, AuditRead,
		slog.String("session_id", e.SessionID),
		slog.String("identity", e.Identity),
		slog.String("resource", e.Resource),
	)
}

func (a *Auditor) emit(ctx context.Context, level slog.Level, event string, attrs ...slog.Attr) {
	a.log.LogAttrs(ctx, level, event, append([]slog.Attr{slog.Bool("audit", true)}, attrs...)...)
}

func clip(s string) string {
	if len(s) <= maxAuditFieldLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxAuditFieldLen], "")
}
