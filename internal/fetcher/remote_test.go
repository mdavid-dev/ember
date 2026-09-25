package fetcher

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRemoteToken = "0123456789abcdef0123456789abcdef"

// fakeDaemon serves whatever envelope the test sets, recording the last
// request it received.
type fakeDaemon struct {
	mu       sync.Mutex
	body     RemoteSnapshot
	status   int
	lastReq  *http.Request
	requests int
}

func (d *fakeDaemon) set(rs RemoteSnapshot) {
	d.mu.Lock()
	d.body = rs
	d.mu.Unlock()
}

func (d *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastReq = r
	d.requests++
	if d.status != 0 {
		http.Error(w, "nope", d.status)
		return
	}
	_ = json.NewEncoder(w).Encode(d.body)
}

func newFakeDaemon(t *testing.T, instance string) (*fakeDaemon, *RemoteFetcher) {
	t.Helper()
	d := &fakeDaemon{}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	f, err := NewRemoteFetcher(srv.URL+"/", testRemoteToken, instance, nil)
	require.NoError(t, err)
	t.Cleanup(f.CloseIdleConnections)
	return d, f
}

func TestNewRemoteFetcher_RejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"ember.prod:9443", "ftp://ember.prod", "https://", "http://[::1"} {
		_, err := NewRemoteFetcher(u, testRemoteToken, "", nil)
		assert.Error(t, err, u)
	}
}

func TestRemoteFetcher_SendsTokenAndInstance(t *testing.T) {
	d, f := newFakeDaemon(t, "blue")
	d.set(RemoteSnapshot{Snapshot: &Snapshot{FetchedAt: time.Now()}})

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, RemoteSnapshotPath, d.lastReq.URL.Path)
	assert.Equal(t, "blue", d.lastReq.URL.Query().Get("instance"))
	assert.Equal(t, "Bearer "+testRemoteToken, d.lastReq.Header.Get("Authorization"))
}

func TestRemoteFetcher_ReturnsSnapshotOncePerDaemonPoll(t *testing.T) {
	d, f := newFakeDaemon(t, "")
	first := time.Now()
	d.set(RemoteSnapshot{Snapshot: &Snapshot{FetchedAt: first, HasFrankenPHP: true}})

	snap, err := f.Fetch(context.Background())
	require.NoError(t, err)
	require.NotNil(t, snap)
	assert.True(t, snap.HasFrankenPHP)

	snap, err = f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Nil(t, snap, "the same snapshot twice would compute every rate over a zero interval")

	d.set(RemoteSnapshot{Snapshot: &Snapshot{FetchedAt: first.Add(time.Second)}})
	snap, err = f.Fetch(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, snap)
}

func TestRemoteFetcher_KeepsInfiniteHistogramBucket(t *testing.T) {
	d, f := newFakeDaemon(t, "")
	d.set(RemoteSnapshot{Snapshot: &Snapshot{
		FetchedAt: time.Now(),
		Metrics: MetricsSnapshot{DurationBuckets: []HistogramBucket{
			{UpperBound: 0.1, CumulativeCount: 1},
			{UpperBound: math.Inf(1), CumulativeCount: 2},
		}},
	}})

	snap, err := f.Fetch(context.Background())

	require.NoError(t, err)
	require.Len(t, snap.Metrics.DurationBuckets, 2, "the +Inf bucket carries the total count percentiles rank against")
	assert.True(t, math.IsInf(snap.Metrics.DurationBuckets[1].UpperBound, 1))
}

func TestRemoteFetcher_StaleSnapshotIsAnError(t *testing.T) {
	d, f := newFakeDaemon(t, "")
	d.set(RemoteSnapshot{Stale: true, Snapshot: &Snapshot{FetchedAt: time.Now().Add(-time.Minute)}})

	snap, err := f.Fetch(context.Background())

	assert.Nil(t, snap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no fresh data")
}

func TestRemoteFetcher_RestoresMetricsFailed(t *testing.T) {
	d, f := newFakeDaemon(t, "")
	d.set(RemoteSnapshot{MetricsFailed: true, Snapshot: &Snapshot{FetchedAt: time.Now()}})

	snap, err := f.Fetch(context.Background())

	require.NoError(t, err)
	assert.True(t, snap.MetricsFailed)
}

func TestRemoteFetcher_HTTPErrors(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "rejected the token"},
		{http.StatusServiceUnavailable, "503"},
		{http.StatusBadRequest, "nope"},
	}
	for _, tt := range tests {
		d, f := newFakeDaemon(t, "")
		d.status = tt.status

		_, err := f.Fetch(context.Background())

		require.Error(t, err, tt.status)
		assert.Contains(t, err.Error(), tt.want)
	}
}

func TestRemoteFetcher_IsReadOnly(t *testing.T) {
	var f any = &RemoteFetcher{}
	_, restarts := f.(interface {
		RestartWorkers(context.Context) error
	})
	assert.False(t, restarts, "a remote session must not restart workers")
}
