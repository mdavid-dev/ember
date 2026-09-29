package exporter

import (
	"net/http"
	"time"
)

// ConfigHandler answers 502 when Caddy fails: the daemon is only the gateway to its admin API.
func ConfigHandler(perInstance map[string]time.Duration, sources map[string]InstanceSource) http.HandlerFunc {
	names := instanceNames(perInstance)
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := resolveInstance(w, r, names, perInstance)
		if !ok {
			return
		}
		raw, err := sources[key].FetchConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(w, raw)
	}
}
