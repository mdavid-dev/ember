package exporter

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
)

// SnapshotHandler serves the latest raw snapshot of one instance, the data a
// remote TUI needs to render the same views as a local one. The instance is
// chosen with ?instance=<name> and is required in multi-instance mode; in
// single-instance mode the parameter is ignored.
//
// The staleness verdict is computed here rather than by the client: comparing
// FetchedAt with the client's clock would break on any clock skew between the
// developer's machine and production.
func SnapshotHandler(holder *StateHolder, defaultInterval time.Duration, perInstance map[string]time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := r.URL.Query().Get("instance")
		entries, multi := holder.entries()
		if !multi {
			name = ""
		} else if name == "" {
			http.Error(w, "instance parameter required; available: "+strings.Join(entryNames(entries), ", "), http.StatusBadRequest)
			return
		}

		slot, _ := holder.lookup(name)
		if slot == nil && multi {
			http.NotFound(w, r)
			return
		}
		if slot == nil || slot.state.Current == nil {
			http.Error(w, "no data yet", http.StatusServiceUnavailable)
			return
		}

		interval := defaultInterval
		if d, ok := perInstance[name]; ok {
			interval = d
		}
		status, _, _ := instanceHealth(slot, staleThresholdFor(interval))

		snap := slot.state.Current
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		encodeJSON(w, fetcher.RemoteSnapshot{
			Instance:      name,
			Stale:         status == healthStale,
			MetricsFailed: snap.MetricsFailed,
			Snapshot:      snap,
		})
	}
}

func entryNames(entries []instanceEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
	}
	return names
}

// BearerAuth wraps an http.Handler with a static bearer token check. Like
// BasicAuth it compares SHA-256 digests in constant time so the response
// timing leaks neither the token nor its length. Every rejected request is
// logged: on an endpoint reachable from outside the infrastructure, failed
// attempts are the first thing an audit looks for.
func BearerAuth(next http.Handler, token string, log *slog.Logger) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		gotHash := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(gotHash[:], want[:]) != 1 {
			log.Warn("remote access denied",
				"remote_addr", r.RemoteAddr,
				"path", r.URL.Path,
				"user_agent", r.UserAgent())
			w.Header().Set("WWW-Authenticate", `Bearer realm="ember remote"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
