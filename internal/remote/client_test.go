package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/internal/fetcher"
)

// swappable lets a test replace the daemon behind a fixed URL, to simulate
// a restart, and count the stream requests it received.
type swappable struct {
	h       atomic.Pointer[http.Handler]
	streams atomic.Int32
}

func (s *swappable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == RouteStream {
		s.streams.Add(1)
	}
	(*s.h.Load()).ServeHTTP(w, r)
}

func (s *swappable) set(h http.Handler) { s.h.Store(&h) }

type clientHarness struct {
	*serverHarness
	front    *swappable
	frontSrv *httptest.Server
	url      string
	sleeps   chan time.Duration
}

func newClientHarness(t *testing.T, instances ...string) *clientHarness {
	t.Helper()
	if len(instances) == 0 {
		instances = []string{DefaultInstance}
	}
	sh := newServerHarness(t, instances, nil)
	front := &swappable{}
	front.set(sh.srv)
	srv := httptest.NewServer(front)
	t.Cleanup(srv.Close)
	return &clientHarness{serverHarness: sh, front: front, frontSrv: srv, url: srv.URL, sleeps: make(chan time.Duration, 64)}
}

// connect uses an instant, recorded backoff so reconnect tests take no time.
func (h *clientHarness) connect(t *testing.T, opts ClientOptions) (*Session, error) {
	t.Helper()
	if opts.URL == "" {
		opts.URL = h.url
	}
	opts.UserAgent = "ember/test"
	s, err := connect(context.Background(), opts, func(s *Session) {
		s.sleep = func(ctx context.Context, d time.Duration) bool {
			select {
			case h.sleeps <- d:
			default:
			}
			return ctx.Err() == nil
		}
	})
	if s != nil {
		t.Cleanup(s.Close)
	}
	return s, err
}

func fetchWithin(t *testing.T, s *Session, d time.Duration) (*fetcher.Snapshot, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return s.Fetch(ctx)
}

// nextSnapshot polls like the TUI does: while the daemon reports an outage,
// Fetch returns the error at once rather than waiting.
func nextSnapshot(t *testing.T, s *Session) *fetcher.Snapshot {
	t.Helper()
	var snap *fetcher.Snapshot
	require.Eventually(t, func() bool {
		got, err := fetchWithin(t, s, 50*time.Millisecond)
		snap = got
		return err == nil
	}, 10*time.Second, 10*time.Millisecond)
	return snap
}

func TestClient_FetchReturnsEachSnapshotOnce(t *testing.T) {
	h := newClientHarness(t)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)

	snap, err := fetchWithin(t, s, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 1.0, snap.Metrics.TotalThreads)

	_, err = fetchWithin(t, s, 200*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded, "no new snapshot: Fetch waits, it never returns (nil, nil)")

	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(2))
	snap, err = fetchWithin(t, s, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 2.0, snap.Metrics.TotalThreads)
	assert.True(t, s.Connected())
}

func TestClient_KeepsMetricsFailed(t *testing.T) {
	h := newClientHarness(t)
	snap := snapWithThreads(1)
	snap.MetricsFailed = true
	h.b.PublishSnapshot(DefaultInstance, snap)
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	got, err := fetchWithin(t, s, 5*time.Second)
	require.NoError(t, err)
	assert.True(t, got.MetricsFailed)
}

func TestClient_ReconnectsWithoutReplayingASnapshot(t *testing.T) {
	h := newClientHarness(t)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	_, err = fetchWithin(t, s, 5*time.Second)
	require.NoError(t, err)

	h.frontSrv.CloseClientConnections()
	require.Eventually(t, func() bool { return h.front.streams.Load() >= 2 && s.Connected() }, 10*time.Second, 10*time.Millisecond)

	_, err = fetchWithin(t, s, 300*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the cached snapshot resent on reconnect was already returned")

	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(3))
	snap, err := fetchWithin(t, s, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 3.0, snap.Metrics.TotalThreads)
}

func TestClient_ReportsTheDaemonsView(t *testing.T) {
	h := newClientHarness(t)
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)

	h.b.PublishFailure(DefaultInstance, errors.New("dial tcp 10.0.0.5:2019: connection refused"))
	require.Eventually(t, func() bool {
		_, err := fetchWithin(t, s, 50*time.Millisecond)
		return err != nil && strings.Contains(err.Error(), "the daemon cannot reach Caddy since")
	}, 10*time.Second, 10*time.Millisecond)
	_, err = fetchWithin(t, s, time.Second)
	require.ErrorContains(t, err, "connection refused")

	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(4))
	assert.Equal(t, 4.0, nextSnapshot(t, s).Metrics.TotalThreads)
	_, err = fetchWithin(t, s, 200*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded, "back to ok: waiting again, no stale error")
}

func TestClient_DetectsADaemonRestart(t *testing.T) {
	h := newClientHarness(t)
	h.b.PublishFailure(DefaultInstance, errors.New("down"))
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	var restarts atomic.Int32
	s.OnEpochChange(func() { restarts.Add(1) })
	require.Eventually(t, func() bool {
		_, err := fetchWithin(t, s, 50*time.Millisecond)
		return err != nil && strings.Contains(err.Error(), "cannot reach Caddy")
	}, 10*time.Second, 10*time.Millisecond)

	restarted := newServerHarness(t, []string{DefaultInstance}, nil)
	restarted.b.PublishSnapshot(DefaultInstance, snapWithThreads(9))
	h.front.set(restarted.srv)
	h.frontSrv.CloseClientConnections()

	assert.Equal(t, 9.0, nextSnapshot(t, s).Metrics.TotalThreads, "a new epoch resets the resume point: its seq 1 is not a replay")
	assert.Equal(t, int32(1), restarts.Load())
	_, err = fetchWithin(t, s, 200*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the old daemon's outage does not outlive it")
}

func TestClient_BackoffGrowsAndIsCapped(t *testing.T) {
	h := newClientHarness(t)
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	require.Eventually(t, s.Connected, 10*time.Second, 10*time.Millisecond)

	h.front.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusServiceUnavailable, ErrorResponse{Error: "too many remote sessions (max 16)"})
	}))
	h.frontSrv.CloseClientConnections()

	var got []time.Duration
	for len(got) < 8 {
		select {
		case d := <-h.sleeps:
			got = append(got, d)
		case <-time.After(10 * time.Second):
			require.FailNow(t, "no reconnect attempt", "got %v", got)
		}
	}
	assert.Equal(t, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second,
	}, got)
	assert.False(t, s.Connected())
	_, err = fetchWithin(t, s, time.Second)
	require.ErrorContains(t, err, "reconnecting to")
	require.ErrorContains(t, err, "too many remote sessions")
}

func TestClient_PermanentRefusalStopsRetrying(t *testing.T) {
	h := newClientHarness(t)
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	require.Eventually(t, s.Connected, 10*time.Second, 10*time.Millisecond)

	swapIdentities(t, h.auth, fmt.Sprintf("[[token]]\nname = \"alice\"\nsha256 = %q\nscopes = [\"snapshot\"]\n", digestOf(aliceToken)))
	h.frontSrv.CloseClientConnections()

	require.Eventually(t, func() bool {
		_, err := fetchWithin(t, s, 50*time.Millisecond)
		return err != nil && strings.Contains(err.Error(), "remote session ended")
	}, 10*time.Second, 10*time.Millisecond)
	streams := h.front.streams.Load()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, streams, h.front.streams.Load(), "a refused token is not retried: it would trip the failure limiter")

	_, err = fetchWithin(t, s, time.Second)
	require.ErrorContains(t, err, "refused the credentials")
	assert.NotContains(t, err.Error(), bobToken)
}

func TestClient_DeadStreamIsReopened(t *testing.T) {
	h := newClientHarness(t)
	h.front.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != RouteStream {
			h.srv.ServeHTTP(w, r)
			return
		}
		// A daemon that goes silent: hello, then not even a ping.
		w.Header().Set("Content-Type", "text/event-stream")
		data, _ := Marshal(Hello{DaemonEpoch: h.b.Epoch(), SessionID: "s", Instance: DefaultInstance})
		_, _ = WriteEvent(w, Event{ID: h.b.nextID(), Type: EventHello, Data: data})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	s, err := connect(context.Background(), ClientOptions{URL: h.url, Token: bobToken}, func(s *Session) {
		s.idle = 100 * time.Millisecond
		s.sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	})
	require.NoError(t, err)
	defer s.Close()
	require.Eventually(t, func() bool { return h.front.streams.Load() >= 3 }, 10*time.Second, 10*time.Millisecond)
}

func TestClient_HandshakeErrors(t *testing.T) {
	h := newClientHarness(t, "api", "web")

	_, err := h.connect(t, ClientOptions{Token: "ember_rt_wrong"})
	require.ErrorContains(t, err, "refused the credentials (check the token or the client certificate) (HTTP 401)")
	assert.NotContains(t, err.Error(), "ember_rt_wrong")

	_, err = h.connect(t, ClientOptions{Token: bobToken})
	require.ErrorContains(t, err, "several instances (api, web): pick one with --remote-instance")

	_, err = h.connect(t, ClientOptions{Token: bobToken, Instance: "db"})
	require.ErrorContains(t, err, `no instance "db" (available: api, web)`)

	s, err := h.connect(t, ClientOptions{Token: bobToken, Instance: "web"})
	require.NoError(t, err)
	assert.Equal(t, "web", s.Instance().Name)

	swapIdentities(t, h.auth, fmt.Sprintf("[[token]]\nname = \"bob\"\nsha256 = %q\nscopes = [\"logs\"]\n", digestOf(bobToken)))
	_, err = h.connect(t, ClientOptions{Token: bobToken, Instance: "web"})
	require.ErrorContains(t, err, `your identity lacks the "snapshot" scope`)
}

func TestClient_ProtocolMismatch(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusUpgradeRequired, ErrorResponse{Error: "no", SupportedProtocols: []int{2, 3}})
	}))
	defer daemon.Close()
	_, err := Connect(context.Background(), ClientOptions{URL: daemon.URL})
	require.ErrorContains(t, err, "daemon speaks remote protocol 2, 3, this ember speaks 1: upgrade ember")

	future := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol": 2})
	}))
	defer future.Close()
	_, err = Connect(context.Background(), ClientOptions{URL: future.URL})
	require.ErrorIs(t, err, ErrUnsupportedProtocol)
}

func TestClient_RefusesPlainHTTPAndRedirects(t *testing.T) {
	for _, u := range []string{"http://ember.example.com:9443", "ftp://x", "ember.example.com:9443", "https://"} {
		_, err := Connect(context.Background(), ClientOptions{URL: u, Token: bobToken})
		require.Error(t, err, u)
		assert.NotContains(t, err.Error(), bobToken)
	}

	var hit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.RedirectHandler(elsewhere.URL+RouteInfo, http.StatusFound))
	defer redirecting.Close()
	_, err := Connect(context.Background(), ClientOptions{URL: redirecting.URL, Token: bobToken})
	require.ErrorContains(t, err, "HTTP 302")
	assert.False(t, hit.Load(), "the token never follows a redirect")
}

func TestClient_SendsItsIdentityHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	h := newClientHarness(t)
	h.front.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		h.srv.ServeHTTP(w, r)
	}))
	_, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "ember/test", got.Get("User-Agent"))
	assert.Equal(t, "1", got.Get(HeaderProtocol))
	assert.Equal(t, "Bearer "+bobToken, got.Get("Authorization"))
}

func TestClient_FetcherIsReadOnly(t *testing.T) {
	h := newClientHarness(t)
	s, err := h.connect(t, ClientOptions{Token: aliceToken})
	require.NoError(t, err)
	f := s.Fetcher()

	_, restarts := f.(interface{ RestartWorkers(context.Context) error })
	_, configs := f.(interface {
		FetchConfig(context.Context) (json.RawMessage, error)
	})
	_, certs := f.(interface {
		FetchPKICertificates(context.Context) []fetcher.CertificateInfo
	})
	assert.False(t, restarts, "the TUI finds worker restart by type assertion")
	assert.False(t, configs)
	assert.False(t, certs)
}

func TestClient_UnavailableSaysWhy(t *testing.T) {
	h := newClientHarness(t)
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		CapabilityLogs:         "Logs unavailable: the daemon was not started with --remote-logs.",
		CapabilityConfig:       "Config unavailable: this daemon does not serve it.",
		CapabilityCertificates: "Certificates unavailable: this daemon does not serve it.",
	}, s.Unavailable())

	s.info.Capabilities = []string{CapabilitySnapshot, CapabilityLogs, CapabilityConfig}
	s.info.Scopes = []string{string(ScopeSnapshot), string(ScopeConfig)}
	assert.Equal(t, `Logs unavailable: your token lacks the "logs" scope.`, s.Unavailable()[CapabilityLogs])
	assert.Equal(t, "Config unavailable: this ember does not read it in remote mode yet.", s.Unavailable()[CapabilityConfig])

	assert.Equal(t, "bob@"+strings.TrimPrefix(h.url, "http://"), s.Badge())
	assert.Equal(t, DefaultInstance, s.Instance().Name)
	assert.Equal(t, "bob", s.Info().Identity)
}

func TestClient_CloseEndsFetch(t *testing.T) {
	h := newClientHarness(t)
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := s.Fetch(context.Background())
		done <- err
	}()
	s.Close()
	select {
	case err := <-done:
		require.ErrorIs(t, err, errSessionClosed)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Fetch still blocked after Close")
	}
}

func TestStatusError_Messages(t *testing.T) {
	assert.Equal(t, "remote daemon: slow down (HTTP 429)", (&StatusError{Code: 429, Body: ErrorResponse{Error: "slow down"}}).Error())
	assert.False(t, (&StatusError{Code: 503}).permanent())
	assert.True(t, (&StatusError{Code: 404}).permanent())
}

func TestClient_FetcherDelegatesToTheSession(t *testing.T) {
	h := newClientHarness(t)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(6))
	s, err := h.connect(t, ClientOptions{Token: bobToken})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := s.Fetcher().Fetch(ctx)
	require.NoError(t, err)
	assert.Equal(t, 6.0, snap.Metrics.TotalThreads)
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "10.0.0.1": false, "ember.example": false} {
		assert.Equal(t, want, isLoopbackHost(host), host)
	}
}

func TestSleepCtx(t *testing.T) {
	assert.True(t, sleepCtx(context.Background(), time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.False(t, sleepCtx(ctx, time.Hour))
}
