package remote

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxSessions  = 16
	defaultWriteTimeout = 10 * time.Second
	defaultPingInterval = 15 * time.Second
)

type ServerConfig struct {
	Auth         *Authenticator
	Audit        *Auditor
	Broadcaster  *Broadcaster
	EmberVersion string
	// Capabilities lists what this daemon serves; snapshot is always included.
	Capabilities []string
	MaxSessions  int
}

// Server is the http.Handler of the remote API. To stop it, close the
// Broadcaster first: streams only end on it, and http.Server.Shutdown waits
// for them.
type Server struct {
	cfg          ServerConfig
	handler      http.Handler
	writeTimeout time.Duration
	pingInterval time.Duration

	mu       sync.Mutex
	sessions map[string]Identity
}

func NewServer(cfg ServerConfig) *Server {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultMaxSessions
	}
	if !slices.Contains(cfg.Capabilities, CapabilitySnapshot) {
		cfg.Capabilities = append([]string{CapabilitySnapshot}, cfg.Capabilities...)
	}
	s := &Server{
		cfg:          cfg,
		writeTimeout: defaultWriteTimeout,
		pingInterval: defaultPingInterval,
		sessions:     make(map[string]Identity),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(RouteInfo, s.serveInfo)
	mux.HandleFunc(RouteStream, s.serveStream)
	mux.HandleFunc(RouteConfig, notServed)
	mux.HandleFunc(RouteCertificates, notServed)
	s.handler = cfg.Auth.Middleware(mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 0)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "the remote API is read-only"})
		return
	}
	// A missing header is refused too: the client must say which layout it expects.
	if v := r.Header.Get(HeaderProtocol); v != strconv.Itoa(ProtocolVersion) {
		writeError(w, http.StatusUpgradeRequired, ErrorResponse{
			Error:              fmt.Sprintf("this daemon speaks remote protocol %d, the request asked for %q", ProtocolVersion, v),
			SupportedProtocols: []int{ProtocolVersion},
		})
		return
	}
	s.handler.ServeHTTP(w, r)
}

func notServed(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, ErrorResponse{Error: "this daemon does not serve " + strings.TrimPrefix(r.URL.Path, RoutePrefix)})
}

func (s *Server) serveInfo(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	// An Info always encodes.
	data, _ := Marshal(Info{
		Protocol:     ProtocolVersion,
		EmberVersion: s.cfg.EmberVersion,
		DaemonEpoch:  s.cfg.Broadcaster.Epoch(),
		Identity:     id.Name,
		Scopes:       id.ScopeNames(),
		Capabilities: s.cfg.Capabilities,
		Instances:    s.cfg.Broadcaster.Instances(),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// resolveInstance applies the single-instance default of ?instance=.
func (s *Server) resolveInstance(w http.ResponseWriter, r *http.Request) (string, bool) {
	var names []string
	for _, inst := range s.cfg.Broadcaster.Instances() {
		names = append(names, inst.Name)
	}
	name := r.URL.Query().Get("instance")
	switch {
	case name == "" && len(names) == 1:
		return names[0], true
	case name == "":
		writeError(w, http.StatusBadRequest, ErrorResponse{Error: "this daemon watches several instances: pass ?instance=", Instances: names})
		return "", false
	case !slices.Contains(names, name):
		writeError(w, http.StatusNotFound, ErrorResponse{Error: fmt.Sprintf("unknown instance %q", name), Instances: names})
		return "", false
	}
	return name, true
}

func (s *Server) openSession(id Identity) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.cfg.MaxSessions {
		return "", false
	}
	sid := rand.Text()
	s.sessions[sid] = id
	return sid, true
}

func (s *Server) closeSession(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sid)
}

func (s *Server) serveStream(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	instance, ok := s.resolveInstance(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/event-stream")
		return
	}
	refused := func(reason RefuseReason) {
		s.cfg.Audit.SessionRefused(r.Context(), SessionRefusedEvent{Identity: id.Name, ClientCN: id.ClientCN, RemoteAddr: r.RemoteAddr, Reason: reason})
	}
	sid, ok := s.openSession(id)
	if !ok {
		refused(RefuseSessionCap)
		writeError(w, http.StatusServiceUnavailable, ErrorResponse{Error: fmt.Sprintf("too many remote sessions (max %d)", s.cfg.MaxSessions)})
		return
	}
	defer s.closeSession(sid)
	sub, err := s.cfg.Broadcaster.Subscribe(instance)
	if err != nil {
		refused(RefuseShutdown)
		writeError(w, http.StatusServiceUnavailable, ErrorResponse{Error: "the daemon is shutting down"})
		return
	}
	defer sub.Close()

	st := &stream{s: s, w: w, rc: http.NewResponseController(w), id: id}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	started := time.Now()
	s.cfg.Audit.SessionOpen(r.Context(), SessionOpenEvent{
		SessionID: sid, Identity: id.Name, ClientCN: id.ClientCN, RemoteAddr: r.RemoteAddr,
		Instance: instance, Scopes: id.ScopeNames(), UserAgent: r.UserAgent(), EmberVersion: emberVersionOf(r.UserAgent()),
	})
	reason := st.run(r, sub, Hello{DaemonEpoch: s.cfg.Broadcaster.Epoch(), SessionID: sid, Instance: instance})
	s.cfg.Audit.SessionClose(r.Context(), SessionCloseEvent{
		SessionID: sid, Identity: id.Name, Duration: time.Since(started), Events: st.events, Bytes: st.bytes, Reason: reason,
	})
}

type stream struct {
	s      *Server
	w      http.ResponseWriter
	rc     *http.ResponseController
	id     Identity
	events int64
	bytes  int64
}

func (st *stream) run(r *http.Request, sub *Subscription, hello Hello) CloseReason {
	b := st.s.cfg.Broadcaster
	data, _ := Marshal(hello)
	if reason, ok := st.send(Event{ID: b.nextID(), Type: EventHello, Data: data}); !ok {
		return reason
	}
	ping := time.NewTimer(st.s.pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return CloseClient
		case <-b.Done():
			return CloseShutdown
		case <-sub.Ready():
			for _, ev := range sub.Take() {
				if reason, ok := st.send(Event{ID: b.eventID(ev), Type: ev.typ, Data: ev.data}); !ok {
					return reason
				}
			}
		case <-ping.C:
			if reason, ok := st.send(Event{}); !ok {
				return reason
			}
		}
		ping.Reset(st.s.pingInterval)
	}
}

// send revalidates the identity, then writes ev; a zero Event is the keep-alive ping.
func (st *stream) send(ev Event) (CloseReason, bool) {
	current, ok := st.s.cfg.Auth.Revalidate(st.id)
	if !ok || !current.Has(ScopeSnapshot) {
		return CloseRevoked, false
	}
	st.id = current
	// Without a deadline a stalled client would pin this goroutine forever.
	deadline := time.Now().Add(st.s.writeTimeout)
	if err := st.rc.SetWriteDeadline(deadline); err != nil {
		return CloseClient, false
	}
	var n int
	var err error
	if ev.Type == "" {
		n, err = WriteComment(st.w, "ping")
	} else {
		n, err = WriteEvent(st.w, ev)
		st.events++
	}
	st.bytes += int64(n)
	if err == nil {
		err = st.rc.Flush()
	}
	switch {
	// HTTP/2 reports an expired deadline as a reset stream, not ErrDeadlineExceeded.
	case errors.Is(err, os.ErrDeadlineExceeded), err != nil && !time.Now().Before(deadline):
		return CloseSlowClient, false
	case err != nil:
		return CloseClient, false
	}
	// A deadline left armed would reset an idle HTTP/2 stream between events.
	if err := st.rc.SetWriteDeadline(time.Time{}); err != nil {
		return CloseClient, false
	}
	return "", true
}

// emberVersionOf reads the version of an "ember/<version>" User-Agent.
func emberVersionOf(ua string) string {
	product, _, _ := strings.Cut(ua, " ")
	if v, ok := strings.CutPrefix(product, "ember/"); ok {
		return v
	}
	return ""
}
