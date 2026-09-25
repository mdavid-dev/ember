package remote

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/pkg/metrics"
)

type serverHarness struct {
	srv   *Server
	b     *Broadcaster
	auth  *Authenticator
	http  *httptest.Server
	audit *lockedBuffer
}

func newServerHarness(t *testing.T, instances []string, configure func(*ServerConfig)) *serverHarness {
	t.Helper()
	ids, err := ParseAuthFile([]byte(testAuthFile()))
	require.NoError(t, err)
	h := &serverHarness{audit: &lockedBuffer{}}
	auditor := NewAuditor(slog.New(slog.NewJSONHandler(h.audit, nil)))
	h.auth = NewAuthenticator(ids, NewRateLimiter(nil), auditor, nil)
	h.b, _ = newTestBroadcaster(instances...)
	cfg := ServerConfig{Auth: h.auth, Audit: auditor, Broadcaster: h.b, EmberVersion: "1.7.0"}
	if configure != nil {
		configure(&cfg)
	}
	h.srv = NewServer(cfg)
	h.http = httptest.NewServer(h.srv)
	t.Cleanup(func() {
		h.b.Close()
		h.http.Close()
	})
	return h
}

func (h *serverHarness) request(t *testing.T, method, path, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, h.http.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set(HeaderProtocol, "1")
	req.Header.Set("User-Agent", "ember/1.7.0 (linux)")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// reply is a response whose body do already read and closed.
type reply struct {
	StatusCode int
	Header     http.Header
}

func (h *serverHarness) do(t *testing.T, req *http.Request) (reply, []byte) {
	t.Helper()
	resp, err := h.http.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{StatusCode: resp.StatusCode, Header: resp.Header}, body
}

type openStream struct {
	resp   *http.Response
	r      *Reader
	cancel context.CancelFunc
}

func (h *serverHarness) open(t *testing.T, path, token string) *openStream {
	t.Helper()
	// The timeout turns a stream that never delivers into a failure, not a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	req := h.request(t, http.MethodGet, path, token).WithContext(ctx)
	resp, err := h.http.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	st := &openStream{resp: resp, r: NewReader(resp.Body, 0), cancel: cancel}
	t.Cleanup(st.close)
	return st
}

func (s *openStream) close() {
	s.cancel()
	s.resp.Body.Close()
}

func (s *openStream) next(t *testing.T, typ string) Event {
	t.Helper()
	ev, err := s.r.Next()
	require.NoError(t, err)
	require.Equal(t, typ, ev.Type)
	return ev
}

// auditEvent waits for an audit record of the given event name.
func (h *serverHarness) auditEvent(t *testing.T, name string) map[string]any {
	t.Helper()
	var found map[string]any
	require.Eventually(t, func() bool {
		for _, line := range strings.Split(strings.TrimSpace(h.audit.String()), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == name {
				found = rec
				return true
			}
		}
		return false
	}, 10*time.Second, 10*time.Millisecond)
	return found
}

func (h *serverHarness) sessions() int {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	return len(h.srv.sessions)
}

func TestServer_RefusesWriteMethods(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		resp, body := h.do(t, h.request(t, m, RouteInfo, aliceToken))
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, m)
		assert.Equal(t, "GET, HEAD", resp.Header.Get("Allow"))
		assert.JSONEq(t, `{"error":"the remote API is read-only"}`, string(body))
	}
}

func TestServer_ProtocolHeader(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	for _, v := range []string{"", "2", "01", "1,2"} {
		req := h.request(t, http.MethodGet, RouteInfo, aliceToken)
		req.Header.Set(HeaderProtocol, v)
		if v == "" {
			req.Header.Del(HeaderProtocol)
		}
		resp, body := h.do(t, req)
		require.Equal(t, http.StatusUpgradeRequired, resp.StatusCode, v)
		er, err := DecodeErrorResponse(body)
		require.NoError(t, err)
		assert.Equal(t, []int{1}, er.SupportedProtocols)
	}
}

func TestServer_Info(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(1))

	resp, body := h.do(t, h.request(t, http.MethodGet, RouteInfo, bobToken))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	info, err := DecodeInfo(body)
	require.NoError(t, err)
	assert.Equal(t, Info{
		Protocol: 1, EmberVersion: "1.7.0", DaemonEpoch: h.b.Epoch(), Identity: "bob",
		Scopes: []string{"snapshot"}, Capabilities: []string{"snapshot"},
		Instances: []InstanceInfo{{Name: DefaultInstance, HasFrankenPHP: true, Interval: Duration(time.Second)}},
	}, info)

	resp, _ = h.do(t, h.request(t, http.MethodGet, RouteInfo, ""))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestServer_EveryRouteAnswersJSON(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	for route := range routeScopes {
		resp, _ := h.do(t, h.request(t, http.MethodHead, route, aliceToken))
		assert.Contains(t, []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode, route)
		if route == RouteStream {
			continue
		}
		resp, body := h.do(t, h.request(t, http.MethodGet, route, aliceToken))
		assert.True(t, json.Valid(body), "%s answered %q", route, body)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"), route)
	}
	_, body := h.do(t, h.request(t, http.MethodGet, RouteConfig, aliceToken))
	assert.JSONEq(t, `{"error":"this daemon does not serve config"}`, string(body))
}

func TestServer_StreamDeliversHelloThenSnapshots(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(4))

	st := h.open(t, RouteStream, aliceToken)
	assert.Equal(t, "text/event-stream", st.resp.Header.Get("Content-Type"))
	ev := st.next(t, EventHello)
	hello, err := DecodeHello(ev.Data)
	require.NoError(t, err)
	assert.Equal(t, h.b.Epoch(), hello.DaemonEpoch)
	assert.Equal(t, DefaultInstance, hello.Instance)
	assert.NotEmpty(t, hello.SessionID)
	_, helloSeq, ok := ParseEventID(ev.ID)
	require.True(t, ok)

	ev = st.next(t, EventSnapshot)
	ws, err := DecodeSnapshot(ev.Data)
	require.NoError(t, err)
	assert.Equal(t, 4.0, ws.Snapshot.Metrics.TotalThreads, "the last known snapshot comes first, without waiting for a poll")
	_, firstSeq, _ := ParseEventID(ev.ID)

	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(5))
	ev = st.next(t, EventSnapshot)
	ws, err = DecodeSnapshot(ev.Data)
	require.NoError(t, err)
	assert.Equal(t, 5.0, ws.Snapshot.Metrics.TotalThreads)
	_, secondSeq, _ := ParseEventID(ev.ID)
	assert.Less(t, firstSeq, secondSeq)
	assert.NotEqual(t, helloSeq, firstSeq)

	open := h.auditEvent(t, AuditSessionOpen)
	assert.Equal(t, hello.SessionID, open["session_id"])
	assert.Equal(t, "alice", open["identity"])
	assert.Equal(t, DefaultInstance, open["instance"])
	assert.Equal(t, "1.7.0", open["ember_version"])

	st.close()
	closed := h.auditEvent(t, AuditSessionClose)
	assert.Equal(t, string(CloseClient), closed["reason"])
	assert.InDelta(t, 3, closed["events"], 0)
	assert.Greater(t, closed["bytes"], 0.0)
}

func TestServer_StreamJoinsMidOutage(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	h.b.PublishFailure(DefaultInstance, errors.New("connection refused"))

	st := h.open(t, RouteStream, bobToken)
	st.next(t, EventHello)
	st.next(t, EventSnapshot)
	status, err := DecodeStatus(st.next(t, EventStatus).Data)
	require.NoError(t, err)
	assert.Equal(t, StateUnreachable, status.State)
}

func TestServer_InstanceResolution(t *testing.T) {
	single := newServerHarness(t, []string{DefaultInstance}, nil)
	single.open(t, RouteStream+"?instance=default", bobToken).next(t, EventHello)
	resp, _ := single.do(t, single.request(t, http.MethodHead, RouteStream+"?instance=web", bobToken))
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	multi := newServerHarness(t, []string{"api", "web"}, nil)
	resp, body := multi.do(t, multi.request(t, http.MethodGet, RouteStream, bobToken))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	er, err := DecodeErrorResponse(body)
	require.NoError(t, err)
	assert.Equal(t, []string{"api", "web"}, er.Instances)

	resp, body = multi.do(t, multi.request(t, http.MethodGet, RouteStream+"?instance=db", bobToken))
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), `unknown instance \"db\"`)

	hello, err := DecodeHello(multi.open(t, RouteStream+"?instance=web", bobToken).next(t, EventHello).Data)
	require.NoError(t, err)
	assert.Equal(t, "web", hello.Instance)
}

func TestServer_SessionCap(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, func(c *ServerConfig) { c.MaxSessions = 2 })

	for range 3 {
		resp, _ := h.do(t, h.request(t, http.MethodHead, RouteStream, bobToken))
		assert.Equal(t, http.StatusOK, resp.StatusCode, "HEAD takes no session")
	}
	first := h.open(t, RouteStream, bobToken)
	first.next(t, EventHello)
	h.open(t, RouteStream, aliceToken).next(t, EventHello)

	resp, body := h.do(t, h.request(t, http.MethodGet, RouteStream, bobToken))
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.JSONEq(t, `{"error":"too many remote sessions (max 2)"}`, string(body))

	first.close()
	require.Eventually(t, func() bool { return h.sessions() == 1 }, 10*time.Second, 10*time.Millisecond)
	h.open(t, RouteStream, bobToken).next(t, EventHello)

	refused := h.auditEvent(t, AuditSessionRefused)
	assert.Equal(t, string(RefuseSessionCap), refused["reason"])
	assert.Equal(t, "bob", refused["identity"])
}

func TestServer_ShutdownClosesStreams(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	st := h.open(t, RouteStream, bobToken)
	st.next(t, EventHello)

	h.b.Close()
	_, err := st.r.Next()
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, string(CloseShutdown), h.auditEvent(t, AuditSessionClose)["reason"])

	resp, _ := h.do(t, h.request(t, http.MethodGet, RouteStream, bobToken))
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Zero(t, h.sessions())
	assert.Equal(t, string(RefuseShutdown), h.auditEvent(t, AuditSessionRefused)["reason"])
}

func swapIdentities(t *testing.T, a *Authenticator, file string) {
	t.Helper()
	ids, err := ParseAuthFile([]byte(file))
	require.NoError(t, err)
	a.ids.Store(ids)
}

func TestServer_RevokedIdentityIsClosedAtTheNextEvent(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	st := h.open(t, RouteStream, bobToken)
	st.next(t, EventHello)

	swapIdentities(t, h.auth, fmt.Sprintf("[[token]]\nname = \"alice\"\nsha256 = %q\nscopes = [\"snapshot\"]\n", digestOf(aliceToken)))
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	_, err := st.r.Next()
	require.ErrorIs(t, err, io.EOF, "the snapshot is not sent to a revoked identity")
	assert.Equal(t, string(CloseRevoked), h.auditEvent(t, AuditSessionClose)["reason"])
}

func TestServer_LosingTheSnapshotScopeRevokesOnPing(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.srv.pingInterval = 20 * time.Millisecond
	st := h.open(t, RouteStream, bobToken)
	st.next(t, EventHello)

	swapIdentities(t, h.auth, fmt.Sprintf("[[token]]\nname = \"bob\"\nsha256 = %q\nscopes = [\"logs\"]\n", digestOf(bobToken)))
	_, err := st.r.Next()
	require.ErrorIs(t, err, io.EOF, "an idle session is revalidated on the ping")
	assert.Equal(t, string(CloseRevoked), h.auditEvent(t, AuditSessionClose)["reason"])
}

func TestServer_KeepAlivePing(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.srv.pingInterval = 20 * time.Millisecond
	req := h.request(t, http.MethodGet, RouteStream, bobToken)
	resp, err := h.http.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	for {
		line, err := br.ReadString('\n')
		require.NoError(t, err)
		if line == ": ping\n" {
			return
		}
	}
}

func bigSnapshot(hosts int) *metrics.Snapshot {
	s := snapWithThreads(1)
	s.Metrics.Hosts = make(map[string]*metrics.HostMetrics, hosts)
	for i := range hosts {
		name := fmt.Sprintf("host-%06d.example", i)
		s.Metrics.Hosts[name] = &metrics.HostMetrics{Host: name, RequestsTotal: float64(i), StatusCodes: map[int]float64{200: 1}}
	}
	return s
}

// publishUntilClosed publishes large snapshots until the one session is gone;
// no single publish may wait on the frozen client.
func publishUntilClosed(t *testing.T, h *serverHarness) {
	t.Helper()
	require.Eventually(t, func() bool { return h.sessions() == 1 }, 10*time.Second, 5*time.Millisecond)
	snap := bigSnapshot(20_000)
	deadline := time.Now().Add(20 * time.Second)
	for h.sessions() == 1 && time.Now().Before(deadline) {
		within(t, 10*time.Second, func() { h.b.PublishSnapshot(DefaultInstance, snap) })
		time.Sleep(20 * time.Millisecond)
	}
	assert.Equal(t, string(CloseSlowClient), h.auditEvent(t, AuditSessionClose)["reason"])
}

func TestServer_SlowClientIsDisconnected(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.srv.writeTimeout = 200 * time.Millisecond

	conn, err := net.Dial("tcp", h.http.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.(*net.TCPConn).SetReadBuffer(4096))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\n%s: 1\r\nAuthorization: Bearer %s\r\n\r\n", RouteStream, HeaderProtocol, bobToken)
	publishUntilClosed(t, h)
}

// Production listeners are TLS, which negotiates HTTP/2: there the stall comes
// from flow control rather than from the socket buffers.
func TestServer_SlowClientIsDisconnectedOverHTTP2(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.srv.writeTimeout = 200 * time.Millisecond
	h2 := httptest.NewUnstartedServer(h.srv)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()

	req := h.request(t, http.MethodGet, RouteStream, bobToken)
	req.URL.Host = h2.Listener.Addr().String()
	req.URL.Scheme = "https"
	resp, err := h2.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor)
	publishUntilClosed(t, h)
}

func TestServer_IdleHTTP2StreamOutlivesTheWriteDeadline(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	h.srv.writeTimeout = 100 * time.Millisecond
	h2 := httptest.NewUnstartedServer(h.srv)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()

	req := h.request(t, http.MethodGet, RouteStream, bobToken)
	req.URL.Host = h2.Listener.Addr().String()
	req.URL.Scheme = "https"
	resp, err := h2.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	r := NewReader(resp.Body, 0)
	_, err = r.Next()
	require.NoError(t, err)

	time.Sleep(5 * h.srv.writeTimeout)
	h.b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	ev, err := r.Next()
	require.NoError(t, err, "a healthy idle stream is not reset")
	assert.Equal(t, EventSnapshot, ev.Type)
}

func TestServer_IgnoresRequestBodies(t *testing.T) {
	h := newServerHarness(t, []string{DefaultInstance}, nil)
	req := h.request(t, http.MethodGet, RouteInfo, bobToken)
	req.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 1<<20)))
	resp, _ := h.do(t, req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestEmberVersionOf(t *testing.T) {
	for ua, want := range map[string]string{
		"ember/1.7.0":         "1.7.0",
		"ember/1.7.0 (linux)": "1.7.0",
		"curl/8.0":            "",
		"":                    "",
		"ember":               "",
	} {
		assert.Equal(t, want, emberVersionOf(ua), ua)
	}
}
