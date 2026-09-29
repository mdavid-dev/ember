package fetcher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type RemoteSnapshot struct {
	Interval time.Duration `json:"interval"`
	Stale    bool          `json:"stale"`
	Snapshot *Snapshot     `json:"snapshot"`
}

type RemoteLogs struct {
	Next    int64      `json:"next"`
	Entries []LogEntry `json:"entries"`
}

// MaxRemoteLogs caps a /logs page: a full one means more lines are waiting.
const MaxRemoteLogs = 1000

// RefusedError is a 4xx answer: the daemon would refuse the same request again.
type RefusedError struct{ error }

// RemoteFetcher cannot restart workers: a remote session is read-only.
type RemoteFetcher struct {
	base       *url.URL
	user, pass string
	userAgent  string
	client     *http.Client
	last       time.Time
}

// NewRemoteFetcher keeps the query of base (e.g. ?instance=) on every request; auth is "user:password" or empty.
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

// Interval also marks the daemon's current snapshot as seen.
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

func (f *RemoteFetcher) FetchPKICertificates(ctx context.Context) []CertificateInfo {
	return f.certificates(ctx, "pki")
}

// DialTLSCertificates ignores hosts: the daemon dials the hosts it monitors.
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

// FetchLogs takes -1 as the first cursor; that request waits while the daemon installs the sinks.
func (f *RemoteFetcher) FetchLogs(ctx context.Context, after int64) (*RemoteLogs, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var page RemoteLogs
	if err := f.do(ctx, "/logs", url.Values{"after": {strconv.FormatInt(after, 10)}}, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

func (f *RemoteFetcher) do(ctx context.Context, path string, params url.Values, out any) error {
	u := *f.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	q := u.Query()
	maps.Copy(q, params)
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
		return RefusedError{errors.New("the daemon rejected the credentials: check EMBER_REMOTE_AUTH or --remote-auth")}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("daemon answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
		if resp.StatusCode < http.StatusInternalServerError {
			return RefusedError{err}
		}
		return err
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode daemon %s: %w", strings.TrimPrefix(path, "/"), err)
	}
	return nil
}
