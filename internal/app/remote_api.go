package app

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/alexandre-daubois/ember/internal/exporter"
	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
)

// remoteAPI serves what a remote TUI needs beyond snapshots: the Caddy
// config, certificates and logs. Every route only reads; none forwards a
// write to the Caddy admin API.
type remoteAPI struct {
	holder    *exporter.StateHolder
	instances map[string]*instance // keyed "" in single-instance mode, like the holder
	multi     bool
	logs      *logRelay // nil when the daemon does not collect logs
}

func newRemoteAPI(holder *exporter.StateHolder, instances []*instance) *remoteAPI {
	api := &remoteAPI{holder: holder, instances: make(map[string]*instance, len(instances)), multi: isMulti(instances)}
	for _, inst := range instances {
		name := inst.name
		if !api.multi {
			name = ""
		}
		api.instances[name] = inst
	}
	return api
}

func (api *remoteAPI) register(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
	mux.Handle(fetcher.RemoteConfigPath, wrap(api.readOnly(api.handleConfig)))
	mux.Handle(fetcher.RemoteCertificatesPath, wrap(api.readOnly(api.handleCertificates)))
	mux.Handle(fetcher.RemoteLogsPath, wrap(api.readOnly(api.handleLogs)))
}

func (api *remoteAPI) readOnly(next func(http.ResponseWriter, *http.Request, string, *instance)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := ""
		if api.multi {
			name = r.URL.Query().Get("instance")
			if name == "" {
				http.Error(w, "instance parameter required", http.StatusBadRequest)
				return
			}
		}
		inst, ok := api.instances[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, name, inst)
	})
}

// handleConfig relays the Caddy config. It can carry secrets (DNS provider
// tokens, upstream credentials): whoever holds the remote token reads them.
func (api *remoteAPI) handleConfig(w http.ResponseWriter, r *http.Request, _ string, inst *instance) {
	raw, err := inst.fetcher.FetchConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// handleCertificates dials the hosts found in the daemon's own last
// snapshot, never hosts named by the client: the daemon sits inside the
// infrastructure, and dialing client-chosen addresses from there would turn
// it into a network probe.
func (api *remoteAPI) handleCertificates(w http.ResponseWriter, r *http.Request, name string, inst *instance) {
	var hosts []string
	if snap := api.holder.Latest(name); snap != nil {
		for h := range snap.Metrics.Hosts {
			hosts = append(hosts, h)
		}
		slices.Sort(hosts)
	}
	certs := inst.fetcher.FetchPKICertificates(r.Context())
	if len(hosts) > 0 {
		certs = append(certs, inst.fetcher.DialTLSCertificates(r.Context(), hosts)...)
	}
	if certs == nil {
		certs = []fetcher.CertificateInfo{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(certs)
}

func (api *remoteAPI) handleLogs(w http.ResponseWriter, r *http.Request, _ string, _ *instance) {
	if api.logs == nil {
		http.Error(w, fetcher.ErrRemoteLogsDisabled.Error(), http.StatusNotFound)
		return
	}
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil && r.URL.Query().Get("after") != "" {
		http.Error(w, "after must be an integer cursor", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.logs.since(after, remoteLogsPageSize))
}

// startLogs has Caddy push its logs to the daemon, which keeps the latest
// ones for remote TUIs. Like the TUI, it registers Ember's sinks in Caddy and
// enables access logs on the servers that had none, and undoes both on
// shutdown. It only runs in single-instance mode, where the log stream
// belongs to one Caddy without ambiguity.
func (api *remoteAPI) startLogs(cfg *config, instances []*instance) func() {
	if api.multi || len(instances) != 1 {
		if cfg.logListen != "" {
			cfg.logger.Warn("--log-listen is ignored by a multi-instance daemon: remote logs need a single Caddy")
		}
		return func() {}
	}
	addr := cfg.logListen
	if addr == "" {
		if !isLocalAdminAddr(instances[0].addr) {
			cfg.logger.Info("remote logs disabled: Caddy is not local and --log-listen was not set")
			return func() {}
		}
		addr = "127.0.0.1:0"
	}
	relay := newLogRelay(remoteLogsCapacity)
	cleanup, advertised, ok := startLogIntake(addr, instances[0].fetcher, relay.append)
	if !ok {
		cfg.logger.Warn("remote logs disabled: cannot listen", "addr", addr)
		return func() {}
	}
	api.logs = relay
	cfg.logger.Info("collecting Caddy logs for remote TUIs", "listen", advertised)
	return cleanup
}

const (
	// remoteLogsCapacity matches the TUI's own log buffer.
	remoteLogsCapacity = model.DefaultLogBufferCapacity
	remoteLogsPageSize = 1_000
)

// logRelay keeps the latest log entries under monotonically increasing
// cursors, so every remote TUI reads the stream at its own pace.
type logRelay struct {
	mu       sync.Mutex
	capacity int
	entries  []fetcher.LogEntry
	first    int64 // cursor of entries[0]; entry i has cursor first+i+1
}

func newLogRelay(capacity int) *logRelay {
	return &logRelay{capacity: capacity}
}

func (l *logRelay) append(batch []fetcher.LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, batch...)
	// Trim in bulk rather than per entry, so appends stay amortised O(1).
	if over := len(l.entries) - l.capacity; over > l.capacity/2 {
		l.entries = slices.Clone(l.entries[over:])
		l.first += int64(over)
	}
}

func (l *logRelay) since(after int64, limit int) fetcher.RemoteLogs {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Serve at most capacity entries even between two trims.
	oldest := l.first + int64(max(len(l.entries)-l.capacity, 0))
	page := fetcher.RemoteLogs{Dropped: after < oldest && after > 0}
	start := max(after, oldest) - l.first
	start = min(start, int64(len(l.entries)))
	end := min(start+int64(limit), int64(len(l.entries)))
	page.Entries = slices.Clone(l.entries[start:end])
	if page.Entries == nil {
		page.Entries = []fetcher.LogEntry{}
	}
	page.Next = l.first + end
	return page
}

// pollRemoteLogs feeds the TUI's log buffers from the daemon, the remote
// counterpart of the net listener. It stops when ctx is cancelled.
func pollRemoteLogs(ctx context.Context, rf *fetcher.RemoteFetcher, interval time.Duration, onBatch func([]fetcher.LogEntry)) {
	var cursor int64
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		// Drain every page available before waiting: the first request
		// returns the daemon's backlog, possibly several pages.
		for {
			reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			page, err := rf.FetchLogs(reqCtx, cursor)
			cancel()
			if err != nil {
				break
			}
			if len(page.Entries) > 0 {
				onBatch(page.Entries)
			}
			cursor = page.Next
			if len(page.Entries) < remoteLogsPageSize {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
