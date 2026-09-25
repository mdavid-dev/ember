package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/exporter"
	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func entries(msgs ...string) []fetcher.LogEntry {
	out := make([]fetcher.LogEntry, len(msgs))
	for i, m := range msgs {
		out[i] = fetcher.LogEntry{Message: m}
	}
	return out
}

func messages(es []fetcher.LogEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Message
	}
	return out
}

func TestLogRelay_CursorPaging(t *testing.T) {
	l := newLogRelay(10)
	l.append(entries("a", "b", "c"))

	page := l.since(0, 2)
	assert.Equal(t, []string{"a", "b"}, messages(page.Entries))
	assert.Equal(t, int64(2), page.Next)

	page = l.since(page.Next, 2)
	assert.Equal(t, []string{"c"}, messages(page.Entries))
	assert.Equal(t, int64(3), page.Next)

	page = l.since(page.Next, 2)
	assert.Empty(t, page.Entries, "a caught-up client gets an empty page")
	assert.NotNil(t, page.Entries, "an empty page encodes as [] rather than null")
	assert.Equal(t, int64(3), page.Next)
	assert.False(t, page.Dropped)
}

func TestLogRelay_ReportsEvictedEntries(t *testing.T) {
	l := newLogRelay(4)
	l.append(entries("1", "2"))
	cursor := l.since(0, 10).Next

	l.append(entries("3", "4", "5", "6", "7", "8", "9"))
	page := l.since(cursor, 10)

	assert.True(t, page.Dropped, "a slow client must learn it missed entries")
	assert.Equal(t, []string{"6", "7", "8", "9"}, messages(page.Entries), "only the latest capacity entries are served")
	assert.Equal(t, int64(9), page.Next)

	assert.False(t, l.since(0, 10).Dropped, "a new client starting from the backlog missed nothing it asked for")
}

// fakeCaddy answers the admin API routes the remote API relies on.
func fakeCaddy(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config/":
			_, _ = w.Write([]byte(`{"apps":{"http":{}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func remoteAPIServer(t *testing.T, withLogs bool) (*fetcher.RemoteFetcher, *remoteAPI) {
	t.Helper()
	caddy := fakeCaddy(t)
	inst := &instance{addr: caddy.URL, fetcher: fetcher.NewHTTPFetcher(caddy.URL, 0), interval: time.Second}
	holder := &exporter.StateHolder{}
	holder.StoreAll(model.State{Current: &fetcher.Snapshot{FetchedAt: time.Now()}}, nil)
	api := newRemoteAPI(holder, []*instance{inst})
	if withLogs {
		api.logs = newLogRelay(100)
	}
	cfg := &config{expose: ":0", daemon: true, interval: time.Second, remoteToken: testToken, logger: discardLogger()}
	srv, err := newExposeServer(cfg, holder, nil, api)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	rf, err := fetcher.NewRemoteFetcher(ts.URL, testToken, "", nil)
	require.NoError(t, err)
	t.Cleanup(rf.CloseIdleConnections)
	return rf, api
}

func TestRemoteAPI_ConfigIsRelayed(t *testing.T) {
	rf, _ := remoteAPIServer(t, false)

	raw, err := rf.FetchConfig(context.Background())

	require.NoError(t, err)
	assert.JSONEq(t, `{"apps":{"http":{}}}`, string(raw))
}

func TestRemoteAPI_CertificatesNeverNull(t *testing.T) {
	rf, _ := remoteAPIServer(t, false)

	certs := rf.FetchPKICertificates(context.Background())

	assert.NotNil(t, certs, "no certificate is an empty list, not a failure")
	assert.Empty(t, certs)
}

func TestRemoteAPI_LogsDisabled(t *testing.T) {
	rf, _ := remoteAPIServer(t, false)

	_, err := rf.FetchLogs(context.Background(), 0)

	require.ErrorIs(t, err, fetcher.ErrRemoteLogsDisabled)
}

func TestRemoteAPI_LogsReachTheClientBuffers(t *testing.T) {
	rf, api := remoteAPIServer(t, true)
	api.logs.append([]fetcher.LogEntry{
		{Logger: "http.log.access", Host: "shop.example", URI: "/cart", Status: 200},
		{Logger: "tls", Message: "certificate renewed"},
	})

	var mu sync.Mutex
	var got []fetcher.LogEntry
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		pollRemoteLogs(ctx, rf, 10*time.Millisecond, func(b []fetcher.LogEntry) {
			mu.Lock()
			got = append(got, b...)
			mu.Unlock()
		})
	}()
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 }, time.Second, 5*time.Millisecond)

	api.logs.append([]fetcher.LogEntry{{Logger: "tls", Message: "later"}})
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 3 }, time.Second, 5*time.Millisecond)
	cancel()
	<-done

	assert.Equal(t, "shop.example", got[0].Host)
	assert.Equal(t, "later", got[2].Message, "entries are read once, in order")
}

func TestRemoteAPI_RejectsWrites(t *testing.T) {
	_, api := remoteAPIServer(t, true)
	mux := http.NewServeMux()
	api.register(mux, func(h http.Handler) http.Handler { return h })

	for _, path := range []string{fetcher.RemoteConfigPath, fetcher.RemoteCertificatesPath, fetcher.RemoteLogsPath} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, path)
	}
}

func TestRemoteAPI_MultiInstanceNeedsName(t *testing.T) {
	a := &instance{name: "blue", fetcher: fetcher.NewHTTPFetcher("http://blue:2019", 0)}
	b := &instance{name: "green", fetcher: fetcher.NewHTTPFetcher("http://green:2019", 0)}
	api := newRemoteAPI(&exporter.StateHolder{}, []*instance{a, b})
	mux := http.NewServeMux()
	api.register(mux, func(h http.Handler) http.Handler { return h })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fetcher.RemoteLogsPath, nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fetcher.RemoteLogsPath+"?instance=red", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fetcher.RemoteLogsPath+"?instance=green", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code, "a multi-instance daemon collects no logs")
	var body map[string]any
	assert.Error(t, json.Unmarshal(rec.Body.Bytes(), &body), "the refusal is a plain-text reason")
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
