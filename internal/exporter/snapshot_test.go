package exporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storeSnapshot(holder *StateHolder, name string, snap *fetcher.Snapshot) {
	var s model.State
	s.Update(snap)
	if name == "" {
		holder.StoreAll(s.CopyForExport(), nil)
		return
	}
	holder.StoreInstance(name, "http://"+name, s.CopyForExport(), nil, nil)
}

func getSnapshot(t *testing.T, h http.Handler, query url.Values) (*httptest.ResponseRecorder, fetcher.RemoteSnapshot) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/snapshot?"+query.Encode(), nil))
	var body fetcher.RemoteSnapshot
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	}
	return rec, body
}

func afterQuery(ts time.Time) url.Values {
	return url.Values{"after": {ts.Format(time.RFC3339Nano)}}
}

var singleIntervals = map[string]time.Duration{"web": 100 * time.Millisecond, "": 100 * time.Millisecond}

func TestSnapshotHandler_ReturnsLatestSnapshot(t *testing.T) {
	holder := &StateHolder{}
	fetchedAt := time.Now()
	storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: fetchedAt})

	start := time.Now()
	rec, body := getSnapshot(t, SnapshotHandler(holder, time.Second, singleIntervals), url.Values{"instance": {"ignored"}})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Less(t, time.Since(start), 100*time.Millisecond, "without after the answer is immediate")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, 100*time.Millisecond, body.Interval)
	assert.False(t, body.Stale)
	require.NotNil(t, body.Snapshot)
	assert.True(t, fetchedAt.Equal(body.Snapshot.FetchedAt))
}

func TestSnapshotHandler_AfterWaitsForNewerSnapshot(t *testing.T) {
	holder := &StateHolder{}
	first := time.Now()
	storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: first})
	intervals := map[string]time.Duration{"web": time.Second, "": time.Second}

	second := first.Add(time.Millisecond)
	go func() {
		time.Sleep(50 * time.Millisecond)
		storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: second})
	}()

	start := time.Now()
	rec, body := getSnapshot(t, SnapshotHandler(holder, time.Second, intervals), afterQuery(first))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Less(t, time.Since(start), time.Second, "the new snapshot must end the wait early")
	assert.True(t, second.Equal(body.Snapshot.FetchedAt))
}

func TestSnapshotHandler_AfterGivesUpAfterTwoIntervals(t *testing.T) {
	holder := &StateHolder{}
	fetchedAt := time.Now()
	storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: fetchedAt})

	start := time.Now()
	rec, body := getSnapshot(t, SnapshotHandler(holder, time.Second, singleIntervals), afterQuery(fetchedAt))
	elapsed := time.Since(start)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond)
	assert.Less(t, elapsed, time.Second)
	assert.True(t, fetchedAt.Equal(body.Snapshot.FetchedAt), "the current snapshot is returned as is")
}

func TestSnapshotHandler_OtherInstanceStoreKeepsWaiting(t *testing.T) {
	holder := &StateHolder{}
	holder.SetMulti(true)
	fetchedAt := time.Now()
	storeSnapshot(holder, "web1", &fetcher.Snapshot{FetchedAt: fetchedAt})
	intervals := map[string]time.Duration{"web1": 100 * time.Millisecond, "web2": 100 * time.Millisecond}

	go func() {
		time.Sleep(20 * time.Millisecond)
		storeSnapshot(holder, "web2", &fetcher.Snapshot{FetchedAt: time.Now()})
	}()

	q := afterQuery(fetchedAt)
	q.Set("instance", "web1")
	start := time.Now()
	rec, body := getSnapshot(t, SnapshotHandler(holder, time.Second, intervals), q)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond)
	assert.True(t, fetchedAt.Equal(body.Snapshot.FetchedAt), "web1's snapshot, not web2's")
}

func TestSnapshotHandler_StaleMatchesHealthz(t *testing.T) {
	for _, age := range []time.Duration{0, 10 * time.Second} {
		holder := &StateHolder{}
		storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: time.Now().Add(-age)})

		_, body := getSnapshot(t, SnapshotHandler(holder, time.Second, singleIntervals), nil)
		health := httptest.NewRecorder()
		HealthHandler(holder, time.Second, singleIntervals)(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))

		assert.Equal(t, health.Code == http.StatusServiceUnavailable, body.Stale, "age %s", age)
	}
}

func TestSnapshotHandler_MultiInstance(t *testing.T) {
	holder := &StateHolder{}
	holder.SetMulti(true)
	web1, web2 := time.Now(), time.Now().Add(time.Second)
	storeSnapshot(holder, "web1", &fetcher.Snapshot{FetchedAt: web1})
	storeSnapshot(holder, "web2", &fetcher.Snapshot{FetchedAt: web2})
	intervals := map[string]time.Duration{"web1": time.Second, "web2": time.Second}
	h := SnapshotHandler(holder, time.Second, intervals)

	rec, _ := getSnapshot(t, h, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "web1, web2")

	rec, _ = getSnapshot(t, h, url.Values{"instance": {"nope"}})
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec, body := getSnapshot(t, h, url.Values{"instance": {"web2"}})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, web2.Equal(body.Snapshot.FetchedAt), "web2's snapshot, not web1's")
}

func TestSnapshotHandler_RejectsMalformedAfter(t *testing.T) {
	rec, _ := getSnapshot(t, SnapshotHandler(&StateHolder{}, time.Second, singleIntervals), url.Values{"after": {"yesterday"}})

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSnapshotHandler_NoDataYet(t *testing.T) {
	rec, _ := getSnapshot(t, SnapshotHandler(&StateHolder{}, time.Second, singleIntervals), nil)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestSnapshotHandler_StopsWaitingWhenClientLeaves(t *testing.T) {
	holder := &StateHolder{}
	fetchedAt := time.Now()
	storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: fetchedAt})
	intervals := map[string]time.Duration{"": time.Minute}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/snapshot?"+afterQuery(fetchedAt).Encode(), nil)
	done := make(chan struct{})
	go func() {
		SnapshotHandler(holder, time.Second, intervals).ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler still waiting after the client went away")
	}
}
