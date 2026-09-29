package exporter

import (
	"cmp"
	"net/http"
	"strconv"

	"github.com/alexandre-daubois/ember/internal/fetcher"
)

type LogSource interface {
	Since(after int64, limit int) ([]fetcher.LogEntry, int64, error)
}

func LogsHandler(src LogSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		after, err := strconv.ParseInt(cmp.Or(r.URL.Query().Get("after"), "-1"), 10, 64)
		if err != nil || after < -1 {
			http.Error(w, "after must be a cursor returned by /logs", http.StatusBadRequest)
			return
		}
		entries, next, err := src.Since(after, fetcher.MaxRemoteLogs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(w, fetcher.RemoteLogs{Next: next, Entries: entries})
	}
}
