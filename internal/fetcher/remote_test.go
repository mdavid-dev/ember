package fetcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRemoteTest(t *testing.T, h http.Handler, auth string) *RemoteFetcher {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := NewRemoteFetcher(u, auth, "test")
	t.Cleanup(f.CloseIdleConnections)
	return f
}

func TestRemoteFetcher_OnlyA4xxIsARefusal(t *testing.T) {
	for status, refused := range map[int]bool{
		http.StatusNotFound:           true,
		http.StatusUnauthorized:       true,
		http.StatusServiceUnavailable: false,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newRemoteTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}), "")

			_, err := f.FetchLogs(context.Background(), -1)

			require.Error(t, err)
			if refused {
				var r RefusedError
				require.ErrorAs(t, err, &r)
				assert.Equal(t, status, r.Status)
			} else {
				assert.NotErrorAs(t, err, new(RefusedError))
			}
		})
	}
}

type seenRequest struct{ path, auth, userAgent string }

type recordingServer struct {
	mu   sync.Mutex
	seen []seenRequest
	next http.Handler
}

func (s *recordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, seenRequest{r.URL.Path, r.Header.Get("Authorization"), r.UserAgent()})
	s.mu.Unlock()
	s.next.ServeHTTP(w, r)
}

func (s *recordingServer) requests() []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenRequest(nil), s.seen...)
}

func TestNewRemoteFetcher_SendsTheCredentialsToTheDaemonOnly(t *testing.T) {
	elsewhere := &recordingServer{next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})}
	other := httptest.NewServer(elsewhere)
	t.Cleanup(other.Close)
	daemon := &recordingServer{next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/caddy/config/" {
			http.Redirect(w, r, other.URL+"/config/", http.StatusFound)
			return
		}
		_ = json.NewEncoder(w).Encode(RemoteLogs{})
	})}
	hf := newRemoteTest(t, daemon, "remote:s3cret")

	hf.DetectFrankenPHP(context.Background())
	_, err := hf.FetchLogs(context.Background(), -1)
	require.NoError(t, err)
	_, err = hf.FetchConfig(context.Background())
	require.NoError(t, err)

	want := "Basic cmVtb3RlOnMzY3JldA==" // remote:s3cret
	got := daemon.requests()
	require.Len(t, got, 3)
	for _, r := range got {
		assert.Equal(t, want, r.auth, r.path)
		assert.Equal(t, "ember/test", r.userAgent, r.path)
	}
	require.Len(t, elsewhere.requests(), 1, "the redirect was followed")
	assert.Empty(t, elsewhere.requests()[0].auth, "no credentials for another host")
	assert.NotContains(t, hf.baseURL, "s3cret", "the password stays out of the URL")
}

func TestRemoteFetcher_TheDaemonDialsTheTLSHosts(t *testing.T) {
	daemon := &recordingServer{next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]CertificateInfo{{Subject: "shop.test", Source: "tls"}})
	})}
	f := newRemoteTest(t, daemon, "")

	certs := f.DialTLSCertificates(context.Background(), []string{"127.0.0.1"})

	require.Len(t, certs, 1)
	assert.Equal(t, "shop.test", certs[0].Subject)
	require.Len(t, daemon.requests(), 1, "the TUI dials nothing itself")
	assert.Equal(t, "/certificates", daemon.requests()[0].path)
}

func TestRemoteFetcher_RefusesToRestartWorkers(t *testing.T) {
	daemon := &recordingServer{next: http.NotFoundHandler()}
	f := newRemoteTest(t, daemon, "")

	err := f.RestartWorkers(context.Background())

	require.EqualError(t, err, "worker restart is not available in a remote session")
	assert.Empty(t, daemon.requests(), "nothing reaches the daemon")
}
