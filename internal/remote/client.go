package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/pkg/metrics"
)

const (
	minReconnectDelay = time.Second
	maxReconnectDelay = 30 * time.Second
	// streamIdleTimeout is three missed pings.
	streamIdleTimeout = 3 * defaultPingInterval
	handshakeTimeout  = 10 * time.Second
)

type ClientOptions struct {
	URL       string
	Token     string
	TLS       *tls.Config
	Instance  string
	UserAgent string
}

// StatusError is a non-2xx answer of the daemon.
type StatusError struct {
	Code int
	Body ErrorResponse
}

func (e *StatusError) Error() string {
	msg := e.Body.Error
	switch e.Code {
	case http.StatusUnauthorized:
		msg = "the daemon refused the credentials (check the token or the client certificate)"
	case http.StatusUpgradeRequired:
		msg = fmt.Sprintf("daemon speaks remote protocol %s, this ember speaks %d: upgrade ember", joinInts(e.Body.SupportedProtocols), ProtocolVersion)
	}
	return fmt.Sprintf("remote daemon: %s (HTTP %d)", msg, e.Code)
}

// permanent reports the answers that retrying cannot fix. Retrying a refused
// token would also trip the daemon's failure limiter and hide the real cause.
func (e *StatusError) permanent() bool {
	switch e.Code {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUpgradeRequired:
		return true
	}
	return false
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// Session is a client connected to a remote daemon. Its stream runs in the
// background, reconnecting with backoff, until Close.
type Session struct {
	opts     ClientOptions
	base     *url.URL
	http     *http.Client
	info     Info
	instance InstanceInfo

	sleep func(context.Context, time.Duration) bool
	idle  time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	ready  chan struct{}

	connected atomic.Bool

	mu        sync.Mutex
	pending   *metrics.Snapshot
	status    Status
	streamErr error
	fatal     error
	epoch     string
	lastSeq   uint64
	onEpoch   func()
}

// Connect runs the handshake, then starts the stream in the background.
func Connect(ctx context.Context, opts ClientOptions) (*Session, error) {
	return connect(ctx, opts, nil)
}

func connect(ctx context.Context, opts ClientOptions, tune func(*Session)) (*Session, error) {
	s, err := newSession(opts)
	if err != nil {
		return nil, err
	}
	if tune != nil {
		tune(s)
	}
	if err := s.handshake(ctx); err != nil {
		return nil, err
	}
	s.start()
	return s, nil
}

func newSession(opts ClientOptions) (*Session, error) {
	base, err := url.Parse(strings.TrimSuffix(opts.URL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("--remote %q: want https://host:port", opts.URL)
	}
	if base.Scheme == "http" && !isLoopbackHost(base.Hostname()) {
		return nil, fmt.Errorf("--remote %q: plain http would send the token in clear; use https", opts.URL)
	}
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   opts.TLS,
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
	}
	s := &Session{
		opts: opts,
		base: base,
		http: &http.Client{
			Transport: tr,
			// A redirect could carry the bearer token to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sleep: sleepCtx,
		idle:  streamIdleTimeout,
		done:  make(chan struct{}),
		ready: make(chan struct{}, 1),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Session) newRequest(ctx context.Context, route string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base.String()+route, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderProtocol, strconv.Itoa(ProtocolVersion))
	req.Header.Set("User-Agent", s.opts.UserAgent)
	if s.opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.opts.Token)
	}
	return req, nil
}

func statusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	er, err := DecodeErrorResponse(body)
	if err != nil || er.Error == "" {
		er = ErrorResponse{Error: http.StatusText(resp.StatusCode)}
	}
	return &StatusError{Code: resp.StatusCode, Body: er}
}

func (s *Session) handshake(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	req, err := s.newRequest(ctx, RouteInfo)
	if err != nil {
		return err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("remote daemon %s: %w", s.base.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("remote daemon %s: %w", s.base.Host, err)
	}
	if s.info, err = DecodeInfo(data); err != nil {
		return err
	}
	if !slices.Contains(s.info.Scopes, string(ScopeSnapshot)) {
		return fmt.Errorf("remote daemon: your identity lacks the %q scope", ScopeSnapshot)
	}
	return s.pickInstance()
}

func (s *Session) pickInstance() error {
	var names []string
	for _, inst := range s.info.Instances {
		names = append(names, inst.Name)
		if inst.Name == s.opts.Instance || (s.opts.Instance == "" && len(s.info.Instances) == 1) {
			s.instance = inst
		}
	}
	switch {
	case s.instance.Name != "":
		return nil
	case s.opts.Instance == "":
		return fmt.Errorf("remote daemon watches several instances (%s): pick one with --remote-instance", strings.Join(names, ", "))
	default:
		return fmt.Errorf("remote daemon has no instance %q (available: %s)", s.opts.Instance, strings.Join(names, ", "))
	}
}

func (s *Session) Info() Info             { return s.info }
func (s *Session) Instance() InstanceInfo { return s.instance }

// Badge names who is connected where, for the TUI header.
func (s *Session) Badge() string { return s.info.Identity + "@" + s.base.Host }

// Connected reports whether the stream is up right now.
func (s *Session) Connected() bool { return s.connected.Load() }

// OnEpochChange registers fn, called when the daemon restarted between two
// streams, so buffers built from the previous daemon can be dropped.
func (s *Session) OnEpochChange(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onEpoch = fn
}

// Unavailable returns, per feature the TUI offers, why it cannot be used in
// this session. A feature absent from the map is available.
func (s *Session) Unavailable() map[string]string {
	out := make(map[string]string)
	for _, f := range []struct{ key, title, flag string }{
		{CapabilityLogs, "Logs", "--remote-logs"},
		{CapabilityConfig, "Config", ""},
		{CapabilityCertificates, "Certificates", ""},
	} {
		switch {
		case !slices.Contains(s.info.Capabilities, f.key) && f.flag != "":
			out[f.key] = fmt.Sprintf("%s unavailable: the daemon was not started with %s.", f.title, f.flag)
		case !slices.Contains(s.info.Capabilities, f.key):
			out[f.key] = fmt.Sprintf("%s unavailable: this daemon does not serve it.", f.title)
		case !slices.Contains(s.info.Scopes, f.key):
			out[f.key] = fmt.Sprintf("%s unavailable: your token lacks the %q scope.", f.title, f.key)
		default:
			out[f.key] = fmt.Sprintf("%s unavailable: this ember does not read it in remote mode yet.", f.title)
		}
	}
	return out
}

// Fetcher returns what the TUI reads snapshots from. Its concrete type only
// has Fetch: the TUI finds its optional capabilities by type assertion, and a
// remote session is read-only.
func (s *Session) Fetcher() fetcher.Fetcher { return snapshotFetcher{s} }

type snapshotFetcher struct{ s *Session }

func (f snapshotFetcher) Fetch(ctx context.Context) (*fetcher.Snapshot, error) { return f.s.Fetch(ctx) }

var errSessionClosed = errors.New("remote session closed")

// Fetch waits for the next snapshot, and returns each one exactly once. While
// the daemon reports its Caddy down, or the stream is down, it returns why.
func (s *Session) Fetch(ctx context.Context) (*metrics.Snapshot, error) {
	for {
		s.mu.Lock()
		snap, err := s.pending, s.fetchErrLocked()
		s.pending = nil
		s.mu.Unlock()
		if snap != nil {
			return snap, nil
		}
		if err != nil {
			return nil, err
		}
		select {
		case <-s.ready:
		case <-s.done:
			return nil, errSessionClosed
		case <-ctx.Done():
			return nil, fmt.Errorf("no snapshot from the remote daemon: %w", ctx.Err())
		}
	}
}

func (s *Session) fetchErrLocked() error {
	switch {
	case s.fatal != nil:
		return fmt.Errorf("remote session ended: %w", s.fatal)
	case s.streamErr != nil:
		return fmt.Errorf("reconnecting to %s…: %w", s.base.Host, s.streamErr)
	case s.status.State == StateUnreachable:
		return fmt.Errorf("the daemon cannot reach Caddy since %s: %s", s.status.Since.Local().Format(time.TimeOnly), s.status.Error)
	case s.status.State == StateStale:
		return fmt.Errorf("the daemon cannot send snapshots since %s: %s", s.status.Since.Local().Format(time.TimeOnly), s.status.Error)
	}
	return nil
}

func (s *Session) wake() {
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// Close stops the stream and waits for it.
func (s *Session) Close() {
	s.cancel()
	<-s.done
}

func (s *Session) start() {
	go func() {
		defer close(s.done)
		defer s.http.CloseIdleConnections()
		s.run()
	}()
}

func (s *Session) run() {
	delay := minReconnectDelay
	for {
		opened, err := s.streamOnce()
		s.connected.Store(false)
		if s.ctx.Err() != nil {
			return
		}
		var se *StatusError
		s.mu.Lock()
		if errors.As(err, &se) && se.permanent() {
			s.fatal = err
		} else {
			s.streamErr = err
		}
		fatal := s.fatal != nil
		s.mu.Unlock()
		s.wake()
		if fatal {
			return
		}
		if opened {
			delay = minReconnectDelay
		}
		if !s.sleep(s.ctx, delay) {
			return
		}
		delay = min(2*delay, maxReconnectDelay)
	}
}

// idleReader cancels the stream when nothing arrives, pings included, within
// d: a half-open connection would otherwise never report an error.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
	d     time.Duration
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	i.timer.Reset(i.d)
	return n, err
}

// streamOnce runs one stream until it fails. opened reports whether the
// daemon accepted it, which resets the reconnect backoff.
func (s *Session) streamOnce() (opened bool, err error) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	req, err := s.newRequest(ctx, RouteStream+"?instance="+url.QueryEscape(s.instance.Name))
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	if s.epoch != "" {
		req.Header.Set("Last-Event-ID", FormatEventID(s.epoch, s.lastSeq))
	}
	s.mu.Unlock()

	resp, err := s.http.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, statusError(resp)
	}

	timer := time.AfterFunc(s.idle, cancel)
	defer timer.Stop()
	r := NewReader(&idleReader{r: resp.Body, timer: timer, d: s.idle}, 0)
	for {
		ev, err := r.Next()
		if err != nil {
			if ctx.Err() != nil && s.ctx.Err() == nil {
				err = fmt.Errorf("no data from the daemon for %s", s.idle)
			}
			return true, err
		}
		if err := s.handle(ev); err != nil {
			return true, err
		}
	}
}

func (s *Session) handle(ev Event) error {
	epoch, seq, _ := ParseEventID(ev.ID)
	switch ev.Type {
	case EventHello:
		h, err := DecodeHello(ev.Data)
		if err != nil {
			return err
		}
		s.mu.Lock()
		restarted := s.epoch != "" && s.epoch != h.DaemonEpoch
		if restarted || s.epoch == "" {
			s.epoch, s.lastSeq = h.DaemonEpoch, 0
		}
		// The daemon resends a status after hello only when it is not ok.
		s.status = Status{}
		s.streamErr = nil
		onEpoch := s.onEpoch
		s.mu.Unlock()
		s.connected.Store(true)
		if restarted && onEpoch != nil {
			onEpoch()
		}
		s.wake()
	case EventSnapshot, EventStatus:
		s.mu.Lock()
		defer s.mu.Unlock()
		// A reconnect resends the cached snapshot under the id already seen.
		if epoch == s.epoch && seq <= s.lastSeq {
			return nil
		}
		if epoch == s.epoch {
			s.lastSeq = seq
		}
		if ev.Type == EventStatus {
			st, err := DecodeStatus(ev.Data)
			if err != nil {
				return err
			}
			s.status = st
		} else {
			ws, err := DecodeSnapshot(ev.Data)
			if err != nil {
				return err
			}
			s.pending = ws.ToSnapshot()
		}
		s.wake()
	}
	return nil
}
