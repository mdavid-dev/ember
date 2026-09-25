package fetcher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Routes a daemon serves to remote TUIs. The version segment lets the wire
// format evolve without breaking older clients silently.
const (
	RemoteSnapshotPath     = "/api/v1/snapshot"
	RemoteConfigPath       = "/api/v1/config"
	RemoteCertificatesPath = "/api/v1/certificates"
	RemoteLogsPath         = "/api/v1/logs"
)

// RemoteSnapshot is the body served on RemoteSnapshotPath. The envelope
// carries what the bare Snapshot cannot: MetricsFailed is excluded from
// Snapshot's JSON form, and Stale is judged on the daemon's clock.
type RemoteSnapshot struct {
	Instance      string    `json:"instance,omitempty"`
	Stale         bool      `json:"stale"`
	MetricsFailed bool      `json:"metricsFailed,omitempty"`
	Snapshot      *Snapshot `json:"snapshot"`
}

// RemoteLogs is the body served on RemoteLogsPath: the entries the daemon
// collected after the cursor the client sent. Next is the cursor to send on
// the following request; Dropped reports that entries between the two
// cursors were evicted before the client read them.
type RemoteLogs struct {
	Next    int64      `json:"next"`
	Dropped bool       `json:"dropped,omitempty"`
	Entries []LogEntry `json:"entries"`
}

// ErrRemoteLogsDisabled reports a daemon that does not collect Caddy logs.
var ErrRemoteLogsDisabled = errors.New("the remote daemon does not collect logs (start it with --log-listen)")

// maxRemoteBodyBytes bounds a body read from the network. A snapshot of a
// large FrankenPHP pool stays well under a megabyte; a full Caddy config or
// a page of raw log lines may be larger.
const maxRemoteBodyBytes = 16 << 20

// RemoteFetcher reads from another Ember process running with --daemon and
// --remote-token, instead of querying a Caddy admin API. It reads snapshots,
// the Caddy config, certificates and logs, but does not implement worker
// restart: the TUI probes it through an optional interface, so a remote
// session cannot act on production.
type RemoteFetcher struct {
	base       url.URL
	instance   string
	token      string
	transport  *http.Transport
	httpClient *http.Client

	mu            sync.Mutex
	lastFetchedAt time.Time
}

// NewRemoteFetcher targets the daemon at baseURL. instance selects one
// monitored Caddy when the daemon polls several. tlsConfig may be nil.
func NewRemoteFetcher(baseURL, token, instance string, tlsConfig *tls.Config) (*RemoteFetcher, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid remote URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("remote URL must start with http:// or https://, got %q", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("remote URL %q has no host", baseURL)
	}
	u.RawQuery = ""

	transport := &http.Transport{
		// A custom TLSClientConfig turns HTTP/2 off unless forced. With it,
		// the snapshot and log polls share one connection, which the daemon
		// audits as one session.
		ForceAttemptHTTP2: true,
		// Cloned: the HTTP/2 setup adds "h2" to NextProtos, which would leak
		// into any other client sharing the caller's config.
		TLSClientConfig:     tlsConfig.Clone(),
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &RemoteFetcher{
		base:       *u,
		instance:   instance,
		token:      token,
		transport:  transport,
		httpClient: &http.Client{Transport: transport, Timeout: requestTimeout},
	}, nil
}

// Host returns the daemon's host:port, for display.
func (f *RemoteFetcher) Host() string {
	return f.base.Host
}

// Fetch returns the daemon's latest snapshot.
//
// It returns (nil, nil) when the daemon has not polled Caddy since the
// previous call: handing the TUI the same snapshot twice would compute every
// rate over a zero interval. The TUI keeps its current view on a nil
// snapshot. A daemon that stopped reaching Caddy keeps serving its last
// snapshot, so Stale turns into an error instead of a frozen screen.
func (f *RemoteFetcher) Fetch(ctx context.Context) (*Snapshot, error) {
	var rs RemoteSnapshot
	if err := f.get(ctx, RemoteSnapshotPath, nil, &rs); err != nil {
		return nil, err
	}
	if rs.Snapshot == nil {
		return nil, errors.New("remote daemon: empty snapshot")
	}
	if rs.Stale {
		return nil, fmt.Errorf("remote daemon has no fresh data since %s (Caddy unreachable from the daemon?)",
			rs.Snapshot.FetchedAt.Format(time.RFC3339))
	}
	rs.Snapshot.MetricsFailed = rs.MetricsFailed

	f.mu.Lock()
	defer f.mu.Unlock()
	if !rs.Snapshot.FetchedAt.After(f.lastFetchedAt) {
		return nil, nil
	}
	f.lastFetchedAt = rs.Snapshot.FetchedAt
	return rs.Snapshot, nil
}

// FetchConfig returns the Caddy config as the daemon reads it.
func (f *RemoteFetcher) FetchConfig(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := f.get(ctx, RemoteConfigPath, nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// FetchPKICertificates returns every certificate the daemon can see: its
// Caddy's PKI CAs and the certificates served on the hosts it monitors,
// dialed from inside the infrastructure.
func (f *RemoteFetcher) FetchPKICertificates(ctx context.Context) []CertificateInfo {
	var certs []CertificateInfo
	if err := f.get(ctx, RemoteCertificatesPath, nil, &certs); err != nil {
		return nil
	}
	return certs
}

// DialTLSCertificates returns nothing: FetchPKICertificates already carries
// the served certificates. Letting a client name the hosts would have the
// daemon dial arbitrary addresses from inside the infrastructure.
func (f *RemoteFetcher) DialTLSCertificates(context.Context, []string) []CertificateInfo {
	return nil
}

// FetchLogs returns the log entries the daemon collected after cursor.
// Start with a zero cursor, then pass the Next of the previous page.
func (f *RemoteFetcher) FetchLogs(ctx context.Context, cursor int64) (RemoteLogs, error) {
	var page RemoteLogs
	err := f.get(ctx, RemoteLogsPath, url.Values{"after": {strconv.FormatInt(cursor, 10)}}, &page)
	return page, err
}

// CloseIdleConnections drains the connection pool on quit.
func (f *RemoteFetcher) CloseIdleConnections() {
	f.transport.CloseIdleConnections()
}

func (f *RemoteFetcher) get(ctx context.Context, path string, query url.Values, out any) error {
	u := f.base
	u.Path += path
	if f.instance != "" {
		if query == nil {
			query = url.Values{}
		}
		query.Set("instance", f.instance)
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remote daemon: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body := io.LimitReader(resp.Body, maxRemoteBodyBytes)
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusUnauthorized:
		return errors.New("remote daemon rejected the token (check --remote-token)")
	case resp.StatusCode == http.StatusNotFound && path == RemoteLogsPath:
		return ErrRemoteLogsDisabled
	default:
		msg, _ := io.ReadAll(io.LimitReader(body, 512))
		return fmt.Errorf("remote daemon: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("remote daemon: decode %s: %w", path, err)
	}
	return nil
}
