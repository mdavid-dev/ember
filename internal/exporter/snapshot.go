package exporter

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
)

// watch reads the slot and its wake-up channel under one lock, so no store slips in between.
func (h *StateHolder) watch(name string) (*instanceSlot, <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.updated == nil {
		h.updated = make(chan struct{})
	}
	return h.instances[name], h.updated
}

func hasSnapshotAfter(slot *instanceSlot, after time.Time) bool {
	return slot != nil && slot.state.Current != nil && (after.IsZero() || slot.state.Current.FetchedAt.After(after))
}

// SnapshotHandler serves /snapshot. With ?after= it holds the answer until a
// newer snapshot is stored, for at most twice the instance's interval.
func SnapshotHandler(holder *StateHolder, defaultInterval time.Duration, perInstance map[string]time.Duration) http.HandlerFunc {
	var names []string
	for name := range perInstance {
		if name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var after time.Time
		if v := q.Get("after"); v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				http.Error(w, "after must be an RFC 3339 date", http.StatusBadRequest)
				return
			}
			after = t
		}

		key := ""
		if len(names) > 1 {
			key = q.Get("instance")
			if key == "" {
				http.Error(w, "instance is required, one of: "+strings.Join(names, ", "), http.StatusBadRequest)
				return
			}
			if _, ok := perInstance[key]; !ok {
				http.Error(w, fmt.Sprintf("unknown instance %q", key), http.StatusNotFound)
				return
			}
		}
		interval := defaultInterval
		if d, ok := perInstance[key]; ok {
			interval = d
		}

		slot, updated := holder.watch(key)
		deadline := time.NewTimer(2 * interval)
		defer deadline.Stop()
	wait:
		for !hasSnapshotAfter(slot, after) {
			select {
			case <-updated:
				slot, updated = holder.watch(key)
			case <-deadline.C:
				break wait
			case <-r.Context().Done():
				return
			}
		}
		if slot == nil || slot.state.Current == nil {
			http.Error(w, healthNoDataYet, http.StatusServiceUnavailable)
			return
		}

		status, _, _ := instanceHealth(slot, staleThresholdFor(interval))
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(w, fetcher.RemoteSnapshot{
			Interval: interval,
			Stale:    status == healthStale,
			Snapshot: slot.state.Current,
		})
	}
}
