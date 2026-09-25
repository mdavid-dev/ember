package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), line)
		records = append(records, rec)
	}
	return records
}

func captureAuditor() (*Auditor, *bytes.Buffer) {
	var buf bytes.Buffer
	return NewAuditor(slog.New(slog.NewJSONHandler(&buf, nil))), &buf
}

func TestAudit_EventKeysArePinned(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		emit  func(a *Auditor)
		event string
		level string
		keys  []string
	}{
		{
			func(a *Auditor) {
				a.AuthDenied(ctx, AuthDeniedEvent{RemoteAddr: "192.0.2.1:1", Reason: DenyExpired, UserAgent: "ember/1.7.0"})
			},
			"remote.auth.denied", "WARN",
			[]string{"remote_addr", "reason", "user_agent", "identity", "client_cn"},
		},
		{
			func(a *Auditor) {
				a.AuthDenied(ctx, AuthDeniedEvent{RemoteAddr: "[2001:db8::1]:1", Reason: DenyRateLimited, Source: "2001:db8::/64", Failures: 10})
			},
			"remote.auth.denied", "WARN",
			[]string{"remote_addr", "reason", "user_agent", "identity", "client_cn", "source", "failures"},
		},
		{
			func(a *Auditor) {
				a.SessionOpen(ctx, SessionOpenEvent{
					SessionID: "s1", Identity: "alice", ClientCN: "alice-laptop", RemoteAddr: "192.0.2.1:1",
					Instance: "default", Scopes: []string{"logs", "snapshot"}, UserAgent: "ua", EmberVersion: "1.7.0",
				})
			},
			"remote.session.open", "INFO",
			[]string{"session_id", "identity", "client_cn", "remote_addr", "instance", "scopes", "user_agent", "ember_version"},
		},
		{
			func(a *Auditor) {
				a.SessionClose(ctx, SessionCloseEvent{SessionID: "s1", Identity: "alice", Duration: 90 * time.Second, Events: 12, Bytes: 4096, Reason: CloseSlowClient})
			},
			"remote.session.close", "INFO",
			[]string{"session_id", "identity", "duration", "events", "bytes", "reason"},
		},
		{
			func(a *Auditor) { a.Read(ctx, ReadEvent{SessionID: "s1", Identity: "alice", Resource: "config"}) },
			"remote.read", "INFO",
			[]string{"session_id", "identity", "resource"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.event+"/"+strings.Join(tc.keys, ","), func(t *testing.T) {
			a, buf := captureAuditor()
			tc.emit(a)
			records := decodeLogLines(t, buf)
			require.Len(t, records, 1)
			rec := records[0]
			assert.Equal(t, tc.event, rec["msg"])
			assert.Equal(t, tc.level, rec["level"])
			assert.Equal(t, true, rec["audit"])

			var keys []string
			for k := range rec {
				if k != "time" && k != "level" && k != "msg" && k != "audit" {
					keys = append(keys, k)
				}
			}
			slices.Sort(keys)
			want := slices.Clone(tc.keys)
			slices.Sort(want)
			assert.Equal(t, want, keys)
		})
	}
}

func TestAudit_Values(t *testing.T) {
	a, buf := captureAuditor()
	a.SessionOpen(context.Background(), SessionOpenEvent{Identity: "alice", Scopes: []string{"logs", "snapshot"}})
	a.SessionClose(context.Background(), SessionCloseEvent{Duration: 1500 * time.Millisecond, Events: 3, Bytes: 10, Reason: CloseRevoked})
	records := decodeLogLines(t, buf)
	require.Len(t, records, 2)
	assert.Equal(t, []any{"logs", "snapshot"}, records[0]["scopes"])
	cn, present := records[0]["client_cn"]
	assert.True(t, present, "client_cn is always present, empty without mTLS")
	assert.Empty(t, cn)
	assert.Equal(t, "revoked", records[1]["reason"])
	assert.InDelta(t, 3, records[1]["events"], 0)
	assert.InDelta(t, float64(1500*time.Millisecond), records[1]["duration"], 0)
}

func TestAudit_ClipsClientSuppliedStrings(t *testing.T) {
	a, buf := captureAuditor()
	long := strings.Repeat("é", maxAuditFieldLen) // two bytes each
	a.AuthDenied(context.Background(), AuthDeniedEvent{UserAgent: long})
	a.SessionOpen(context.Background(), SessionOpenEvent{UserAgent: "short", EmberVersion: long})

	records := decodeLogLines(t, buf)
	ua := records[0]["user_agent"].(string)
	assert.Len(t, ua, maxAuditFieldLen, "cut on a rune boundary")
	assert.True(t, strings.HasPrefix(long, ua))
	assert.Equal(t, "short", records[1]["user_agent"])
	assert.LessOrEqual(t, len(records[1]["ember_version"].(string)), maxAuditFieldLen)

	odd := "x" + strings.Repeat("é", maxAuditFieldLen)
	assert.Len(t, clip(odd), maxAuditFieldLen-1, "a split rune is dropped, not mangled")
}

func TestAudit_NilLoggerDiscards(t *testing.T) {
	a := NewAuditor(nil)
	a.AuthDenied(context.Background(), AuthDeniedEvent{Reason: DenyMissing})
}
