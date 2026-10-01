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
	"time"
)

// RemoteLogs is a page of /logs and the cursor of the next one.
type RemoteLogs struct {
	Next    int64      `json:"next"`
	Entries []LogEntry `json:"entries"`
}

// MaxRemoteLogs caps a /logs page: a full one means more lines are waiting.
const MaxRemoteLogs = 1000

// RefusedError is a 4xx answer: the daemon would refuse the same request again.
type RefusedError struct {
	error
	Status int
}

// RemoteFetcher reads Caddy through the /caddy relay of a --serve-remote
// daemon, and the daemon's own /logs and /certificates.
type RemoteFetcher struct {
	*HTTPFetcher
	base *url.URL
}

// NewRemoteFetcher takes auth as "user:password" or empty.
func NewRemoteFetcher(base *url.URL, auth string, tlsCfg *tls.Config, version string) *RemoteFetcher {
	hf := NewHTTPFetcher(base.JoinPath("caddy").String(), 0)
	hf.SetTLSConfig(tlsCfg)
	user, pass, _ := strings.Cut(auth, ":")
	hf.httpClient.Transport = &remoteAuth{next: hf.transport, host: base.Host, user: user, pass: pass, userAgent: "ember/" + version}
	return &RemoteFetcher{HTTPFetcher: hf, base: base}
}

// DialTLSCertificates ignores hosts: the daemon dials the hosts it monitors.
func (f *RemoteFetcher) DialTLSCertificates(ctx context.Context, _ []string) []CertificateInfo {
	var certs []CertificateInfo
	if err := f.do(ctx, "/certificates", nil, &certs); err != nil {
		return nil
	}
	return certs
}

// remoteAuth signs at the transport: HTTPFetcher builds its requests itself.
type remoteAuth struct {
	next                        http.RoundTripper
	host, user, pass, userAgent string
}

func (t *remoteAuth) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", t.userAgent)
	// The client follows redirects: the credentials go to the daemon only.
	if t.user != "" && r.URL.Host == t.host {
		r.SetBasicAuth(t.user, t.pass)
	}
	return t.next.RoundTrip(r)
}

// FetchLogs takes -1 as the first cursor; that request waits while the daemon
// installs the sinks.
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
	u := f.base.JoinPath(path)
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := f.httpClient.Do(req)
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
		return RefusedError{errors.New("the daemon rejected the credentials: check EMBER_REMOTE_AUTH or --remote-auth"), resp.StatusCode}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("daemon answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
		if resp.StatusCode < http.StatusInternalServerError {
			return RefusedError{err, resp.StatusCode}
		}
		return err
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode daemon %s: %w", strings.TrimPrefix(path, "/"), err)
	}
	return nil
}
