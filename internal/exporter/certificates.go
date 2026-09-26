package exporter

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
)

// CertSource reads the certificates of one Caddy instance.
type CertSource interface {
	FetchPKICertificates(ctx context.Context) []fetcher.CertificateInfo
	DialTLSCertificates(ctx context.Context, hosts []string) []fetcher.CertificateInfo
}

// CertificatesHandler serves /certificates?source=pki|tls. The TLS source dials
// the hosts of the daemon's own snapshot, never hosts named by the client.
func CertificatesHandler(holder *StateHolder, perInstance map[string]time.Duration, sources map[string]CertSource) http.HandlerFunc {
	names := instanceNames(perInstance)
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := resolveInstance(w, r, names, perInstance)
		if !ok {
			return
		}
		src := sources[key]
		var certs []fetcher.CertificateInfo
		switch r.URL.Query().Get("source") {
		case "pki":
			certs = src.FetchPKICertificates(r.Context())
		case "tls":
			certs = src.DialTLSCertificates(r.Context(), snapshotHosts(holder, key))
		default:
			http.Error(w, `source must be "pki" or "tls"`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(w, certs)
	}
}

func snapshotHosts(holder *StateHolder, key string) []string {
	slot, _ := holder.lookup(key)
	if slot == nil || slot.state.Current == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(slot.state.Current.Metrics.Hosts))
}
