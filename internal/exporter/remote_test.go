package exporter

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stateFetchedAt(at time.Time) model.State {
	return model.State{Current: &fetcher.Snapshot{
		FetchedAt: at,
		Threads:   fetcher.ThreadsResponse{ThreadDebugStates: []fetcher.ThreadDebugState{{Index: 3, Name: "php-3"}}},
		Metrics:   fetcher.MetricsSnapshot{HTTPRequestsTotal: 42, HasHTTPMetrics: true},
	}}
}

func getSnapshot(t *testing.T, holder *StateHolder, target string) (*httptest.ResponseRecorder, fetcher.RemoteSnapshot) {
	t.Helper()
	h := SnapshotHandler(holder, time.Second, nil)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, target, nil))
	var body fetcher.RemoteSnapshot
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	}
	return rec, body
}

func TestSnapshotHandler_NoDataYet(t *testing.T) {
	rec, _ := getSnapshot(t, &StateHolder{}, "/api/v1/snapshot")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestSnapshotHandler_SingleInstanceServesLatestSnapshot(t *testing.T) {
	holder := &StateHolder{}
	holder.StoreAll(stateFetchedAt(time.Now()), nil)

	rec, body := getSnapshot(t, holder, "/api/v1/snapshot?instance=ignored")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.False(t, body.Stale)
	require.NotNil(t, body.Snapshot)
	assert.InDelta(t, 42.0, body.Snapshot.Metrics.HTTPRequestsTotal, 0)
	require.Len(t, body.Snapshot.Threads.ThreadDebugStates, 1)
	assert.Equal(t, "php-3", body.Snapshot.Threads.ThreadDebugStates[0].Name)
}

func TestSnapshotHandler_FlagsStaleSnapshot(t *testing.T) {
	holder := &StateHolder{}
	holder.StoreAll(stateFetchedAt(time.Now().Add(-time.Minute)), nil)

	rec, body := getSnapshot(t, holder, "/api/v1/snapshot")

	require.Equal(t, http.StatusOK, rec.Code, "a stale snapshot is still served, flagged")
	assert.True(t, body.Stale)
}

func TestSnapshotHandler_CarriesMetricsFailed(t *testing.T) {
	holder := &StateHolder{}
	s := stateFetchedAt(time.Now())
	s.Current.MetricsFailed = true
	holder.StoreAll(s, nil)

	_, body := getSnapshot(t, holder, "/api/v1/snapshot")

	assert.True(t, body.MetricsFailed, "MetricsFailed is excluded from Snapshot's JSON, the envelope must carry it")
}

func TestSnapshotHandler_MultiInstance(t *testing.T) {
	holder := &StateHolder{}
	holder.SetMulti(true)
	holder.StoreInstance("blue", "http://blue:2019", stateFetchedAt(time.Now()), nil, nil)
	holder.StoreInstance("green", "http://green:2019", stateFetchedAt(time.Now()), nil, nil)

	rec, _ := getSnapshot(t, holder, "/api/v1/snapshot")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "blue, green", "the error lists the instances to choose from")

	rec, _ = getSnapshot(t, holder, "/api/v1/snapshot?instance=red")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec, body := getSnapshot(t, holder, "/api/v1/snapshot?instance=green")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "green", body.Instance)
}

func TestSnapshotHandler_RejectsWrites(t *testing.T) {
	holder := &StateHolder{}
	holder.StoreAll(stateFetchedAt(time.Now()), nil)
	rec := httptest.NewRecorder()

	SnapshotHandler(holder, time.Second, nil)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil))

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestBearerAuth(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"valid token", "Bearer " + token, http.StatusNoContent},
		{"missing header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"token prefix", "Bearer " + token[:16], http.StatusUnauthorized},
		{"basic scheme", "Basic " + token, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			h := BearerAuth(ok, token, slog.New(slog.NewTextHandler(&logs, nil)))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.Equal(t, tt.want, rec.Code)
			if tt.want == http.StatusUnauthorized {
				assert.Equal(t, `Bearer realm="ember remote"`, rec.Header().Get("WWW-Authenticate"))
				assert.Contains(t, logs.String(), "remote access denied", "every rejected attempt is logged")
				assert.NotContains(t, logs.String(), token, "the log must never contain the token")
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}
}
