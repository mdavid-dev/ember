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

// RemoteFetcher reads snapshots and certificates from an Ember daemon started
// with --serve-remote. It cannot restart workers: a remote session is read-only.
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
	q := url.Values{}
	if !after.IsZero() {
		q.Set("after", after.Format(time.RFC3339Nano))
	}
	var env RemoteSnapshot
	if err := f.do(ctx, "/snapshot", q, &env); err != nil {
		return nil, err
	}
	if env.Snapshot == nil {
		return nil, errors.New("daemon answered without a snapshot")
	}
	return &env, nil
}

// FetchPKICertificates returns the certificates of the daemon's Caddy PKI.
func (f *RemoteFetcher) FetchPKICertificates(ctx context.Context) []CertificateInfo {
	return f.certificates(ctx, "pki")
}

// DialTLSCertificates returns the certificates served on the hosts the daemon
// monitors: the daemon picks the hosts, so hosts is ignored.
func (f *RemoteFetcher) DialTLSCertificates(ctx context.Context, _ []string) []CertificateInfo {
	return f.certificates(ctx, "tls")
}

func (f *RemoteFetcher) certificates(ctx context.Context, source string) []CertificateInfo {
	var certs []CertificateInfo
	if err := f.do(ctx, "/certificates", url.Values{"source": {source}}, &certs); err != nil {
		return nil
	}
	return certs
}

func (f *RemoteFetcher) do(ctx context.Context, path string, params url.Values, out any) error {
	u := *f.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", f.userAgent)
	if f.user != "" {
		req.SetBasicAuth(f.user, f.pass)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return errors.New("the daemon rejected the credentials: check EMBER_REMOTE_AUTH or --remote-auth")
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("daemon answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode daemon %s: %w", strings.TrimPrefix(path, "/"), err)
	}
	return nil
}
