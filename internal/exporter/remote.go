package exporter

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

func instanceNames(perInstance map[string]time.Duration) []string {
	var names []string
	for name := range perInstance {
		if name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// resolveInstance returns the holder key that ?instance= designates, required
// on a multi-instance daemon, or answers the error itself.
func resolveInstance(w http.ResponseWriter, r *http.Request, names []string, perInstance map[string]time.Duration) (string, bool) {
	if len(names) <= 1 {
		return "", true
	}
	key := r.URL.Query().Get("instance")
	if key == "" {
		http.Error(w, "instance is required, one of: "+strings.Join(names, ", "), http.StatusBadRequest)
		return "", false
	}
	if _, ok := perInstance[key]; !ok {
		http.Error(w, fmt.Sprintf("unknown instance %q", key), http.StatusNotFound)
		return "", false
	}
	return key, true
}
