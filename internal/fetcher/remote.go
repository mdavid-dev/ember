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
	"strings"
	"time"
)

// RemoteSnapshot is the body of the daemon's /snapshot route.
type RemoteSnapshot struct {
	Interval time.Duration `json:"interval"`
	Stale    bool          `json:"stale"`
	Snapshot *Snapshot     `json:"snapshot"`
}

// RemoteFetcher reads snapshots from an Ember daemon started with
// --serve-remote. It only implements Fetch: a remote session is read-only.
type RemoteFetcher struct {
	base       *url.URL
	user, pass string
	userAgent  string
	client     *http.Client
	last       time.Time
}

// NewRemoteFetcher targets the daemon at base, whose query (e.g. ?instance=)
// is kept on every request. auth is "user:password" or empty.
func NewRemoteFetcher(base *url.URL, auth string, tlsCfg *tls.Config, version string) *RemoteFetcher {
	user, pass, _ := strings.Cut(auth, ":")
	return &RemoteFetcher{
		base:      base,
		user:      user,
		pass:      pass,
		userAgent: "ember/" + version,
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     30 * time.Second,
		}},
	}
}

// Interval asks the daemon for its polling interval and marks its current snapshot as seen.
func (f *RemoteFetcher) Interval(ctx context.Context) (time.Duration, error) {
	env, err := f.get(ctx, time.Time{})
	if err != nil {
		return 0, err
	}
	f.last = env.Snapshot.FetchedAt
	return env.Interval, nil
}

func (f *RemoteFetcher) Fetch(ctx context.Context) (*Snapshot, error) {
	env, err := f.get(ctx, f.last)
	if err != nil {
		return nil, err
	}
	if env.Stale {
		return nil, fmt.Errorf("the daemon has not reached Caddy since %s", env.Snapshot.FetchedAt.Local().Format(time.DateTime))
	}
	if !env.Snapshot.FetchedAt.After(f.last) {
		return nil, fmt.Errorf("no new snapshot from the daemon since %s", f.last.Local().Format(time.DateTime))
	}
	f.last = env.Snapshot.FetchedAt
	return env.Snapshot, nil
}

func (f *RemoteFetcher) CloseIdleConnections() {
	f.client.CloseIdleConnections()
}

func (f *RemoteFetcher) get(ctx context.Context, after time.Time) (*RemoteSnapshot, error) {
	u := *f.base
	u.Path = strings.TrimRight(u.Path, "/") + "/snapshot"
	q := u.Query()
	if !after.IsZero() {
		q.Set("after", after.Format(time.RFC3339Nano))
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	if f.user != "" {
		req.SetBasicAuth(f.user, f.pass)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, errors.New("the daemon rejected the credentials: check EMBER_REMOTE_AUTH or --remote-auth")
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("daemon answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var env RemoteSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode daemon snapshot: %w", err)
	}
	if env.Snapshot == nil {
		return nil, errors.New("daemon answered without a snapshot")
	}
	return &env, nil
}
