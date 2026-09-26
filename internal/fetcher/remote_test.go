package fetcher

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDaemon answers /snapshot with the envelopes queued in replies, one per
// request, and records each request's query.
type fakeDaemon struct {
	mu      sync.Mutex
	replies []RemoteSnapshot
	queries []url.Values
}

func (d *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = append(d.queries, r.URL.Query())
	env := d.replies[0]
	if len(d.replies) > 1 {
		d.replies = d.replies[1:]
	}
	_ = json.NewEncoder(w).Encode(env)
}

func newRemoteTest(t *testing.T, d *fakeDaemon, query string) *RemoteFetcher {
	t.Helper()
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + query)
	require.NoError(t, err)
	f := NewRemoteFetcher(u, "", nil, "test")
	t.Cleanup(f.CloseIdleConnections)
	return f
}

func envAt(ts time.Time) RemoteSnapshot {
	return RemoteSnapshot{Interval: time.Second, Snapshot: &Snapshot{FetchedAt: ts}}
}

func TestRemoteFetcher_EachSnapshotOnceInOrder(t *testing.T) {
	t0 := time.Now()
	t1, t2 := t0.Add(time.Second), t0.Add(2*time.Second)
	d := &fakeDaemon{replies: []RemoteSnapshot{envAt(t0), envAt(t1), envAt(t1), envAt(t2)}}
	f := newRemoteTest(t, d, "")

	var got []time.Time
	var errs int
	for range 4 {
		snap, err := f.Fetch(context.Background())
		if err != nil {
			require.Nil(t, snap)
			errs++
			continue
		}
		require.NotNil(t, snap)
		got = append(got, snap.FetchedAt)
	}

	require.Len(t, got, 3)
	assert.True(t, got[0].Equal(t0))
	assert.True(t, got[1].Equal(t1))
	assert.True(t, got[2].Equal(t2))
	assert.Equal(t, 1, errs, "the repeated snapshot is an error, not a duplicate")
	assert.Empty(t, d.queries[0].Get("after"))
	assert.Equal(t, t1.Format(time.RFC3339Nano), d.queries[3].Get("after"))
}

func TestRemoteFetcher_OnlyTheIntervalRequestOmitsAfter(t *testing.T) {
	t0 := time.Now()
	d := &fakeDaemon{replies: []RemoteSnapshot{envAt(t0), envAt(t0.Add(time.Second))}}
	f := newRemoteTest(t, d, "")

	_, err := f.Interval(context.Background())
	require.NoError(t, err)
	_, err = f.Fetch(context.Background())
	require.NoError(t, err)

	assert.False(t, d.queries[0].Has("after"))
	assert.Equal(t, t0.Format(time.RFC3339Nano), d.queries[1].Get("after"))
}

func TestRemoteFetcher_StaleIsAnErrorUntilRecovery(t *testing.T) {
	t0 := time.Now()
	stale := envAt(t0)
	stale.Stale = true
	d := &fakeDaemon{replies: []RemoteSnapshot{stale, envAt(t0.Add(time.Second))}}
	f := newRemoteTest(t, d, "")

	snap, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Nil(t, snap)
	assert.Contains(t, err.Error(), "the daemon has not reached Caddy since")

	snap, err = f.Fetch(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, snap)
}

func TestRemoteFetcher_ReportsDaemonErrors(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
		want       []string
	}{
		{"unauthorized", "", http.StatusUnauthorized, []string{"rejected the credentials", "EMBER_REMOTE_AUTH"}},
		{"other status", "nope", http.StatusBadRequest, []string{"400", "nope"}},
		{"no snapshot", "{}", http.StatusOK, []string{"without a snapshot"}},
		{"broken JSON", "{", http.StatusOK, []string{"decode daemon snapshot"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			t.Cleanup(srv.Close)
			u, err := url.Parse(srv.URL)
			require.NoError(t, err)
			f := NewRemoteFetcher(u, "", nil, "test")
			t.Cleanup(f.CloseIdleConnections)

			_, err = f.Fetch(context.Background())

			require.Error(t, err)
			for _, w := range tt.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}
}

func TestRemoteFetcher_KeepsTheURLQueryAndSendsCredentials(t *testing.T) {
	var gotUser, gotPass, gotUA, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		gotUA, gotPath = r.UserAgent(), r.URL.Path
		assert.Equal(t, "web2", r.URL.Query().Get("instance"))
		_ = json.NewEncoder(w).Encode(envAt(time.Now()))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/?instance=web2")
	require.NoError(t, err)
	f := NewRemoteFetcher(u, "alice:secret", nil, "1.2.3")
	t.Cleanup(f.CloseIdleConnections)

	interval, err := f.Interval(context.Background())

	require.NoError(t, err)
	assert.Equal(t, time.Second, interval)
	assert.Equal(t, "/snapshot", gotPath)
	assert.Equal(t, "alice", gotUser)
	assert.Equal(t, "secret", gotPass)
	assert.Equal(t, "ember/1.2.3", gotUA)
}

func TestRemoteFetcher_IsReadOnly(t *testing.T) {
	var f any = &RemoteFetcher{}

	_, restarts := f.(interface{ RestartWorkers(context.Context) error })
	_, configs := f.(interface {
		FetchConfig(context.Context) (json.RawMessage, error)
	})

	assert.False(t, restarts)
	assert.False(t, configs)
}

func TestRemoteFetcher_ReusesOneConnection(t *testing.T) {
	var n atomic.Int64
	var conns atomic.Int32
	// The JSON is flushed before the handler returns, so the end of the
	// chunked body reaches the client after the decoder is done with it.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(envAt(time.Unix(n.Add(1), 0)))
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := NewRemoteFetcher(u, "", nil, "test")
	t.Cleanup(f.CloseIdleConnections)

	for range 3 {
		_, err := f.Fetch(context.Background())
		require.NoError(t, err)
	}

	assert.Equal(t, int32(1), conns.Load())
}

func TestRemoteFetcher_CertificatesComeFromTheDaemon(t *testing.T) {
	var sources []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/certificates", r.URL.Path)
		user, _, _ := r.BasicAuth()
		assert.Equal(t, "alice", user)
		sources = append(sources, r.URL.Query().Get("source"))
		_ = json.NewEncoder(w).Encode([]CertificateInfo{{Subject: r.URL.Query().Get("source")}})
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := NewRemoteFetcher(u, "alice:secret", nil, "test")
	t.Cleanup(f.CloseIdleConnections)

	pki := f.FetchPKICertificates(context.Background())
	tls := f.DialTLSCertificates(context.Background(), []string{"ignored.example"})

	assert.Equal(t, []string{"pki", "tls"}, sources)
	require.Len(t, pki, 1)
	assert.Equal(t, "pki", pki[0].Subject)
	require.Len(t, tls, 1)
	assert.Equal(t, "tls", tls[0].Subject)
}

func TestRemoteFetcher_CertificatesOnErrorAreEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := NewRemoteFetcher(u, "", nil, "test")
	t.Cleanup(f.CloseIdleConnections)

	assert.Empty(t, f.FetchPKICertificates(context.Background()))
}
