package remote

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	aliceToken = "ember_rt_Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"
	bobToken   = "ember_rt_YmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG9mcmVk"
	carolToken = "ember_rt_Y2Fyb2xjYXJvbGNhcm9sY2Fyb2xjYXJvbGNhcm9sY2Fyb2w"
)

func digestOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// testAuthFile: alice has every scope, bob only snapshot, carol expired before fixtureTime.
func testAuthFile() string {
	return fmt.Sprintf(`
[[token]]
name   = "alice"
sha256 = %q
scopes = ["snapshot", "logs", "config", "certificates"]

[[token]]
name    = "bob"
sha256  = %q
scopes  = ["snapshot"]
expires = 2030-01-01T00:00:00Z

[[token]]
name    = "carol"
sha256  = %q
scopes  = ["snapshot"]
expires = 2026-09-25T00:00:00Z

[[client_cert]]
cn     = "dave"
scopes = ["logs", "snapshot"]
`, digestOf(aliceToken), digestOf(bobToken), digestOf(carolToken))
}

type authHarness struct {
	auth    *Authenticator
	clock   *fakeClock
	logs    *bytes.Buffer
	handler http.Handler
}

func newAuthHarness(t *testing.T, file string) *authHarness {
	t.Helper()
	ids, err := ParseAuthFile([]byte(file))
	require.NoError(t, err)
	h := &authHarness{clock: &fakeClock{t: fixtureTime}, logs: &bytes.Buffer{}}
	log := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.auth = NewAuthenticator(ids, NewRateLimiter(h.clock.Now), NewAuditor(log), h.clock.Now)
	h.handler = h.auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFrom(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s|%s|%s", id.Name, id.ClientCN, strings.Join(id.ScopeNames(), ","))
	}))
	return h
}

func (h *authHarness) do(path, remoteAddr string, headers map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func bearer(token string) map[string][]string {
	return map[string][]string{"Authorization": {"Bearer " + token}}
}

func (h *authHarness) auditRecords(t *testing.T) []map[string]any {
	t.Helper()
	return decodeLogLines(t, h.logs)
}

func TestParseAuthFile_Valid(t *testing.T) {
	ids, err := ParseAuthFile([]byte(testAuthFile()))
	require.NoError(t, err)
	require.Len(t, ids.tokens, 3)
	assert.Equal(t, "alice", ids.tokens[0].name)
	assert.Equal(t, []Scope{ScopeCertificates, ScopeConfig, ScopeLogs, ScopeSnapshot}, ids.tokens[0].scopes, "scopes are sorted")
	assert.True(t, ids.tokens[0].expires.IsZero())
	assert.Equal(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), ids.tokens[1].expires.UTC())
	assert.True(t, ids.HasClientCerts())
	assert.Equal(t, []Scope{ScopeLogs, ScopeSnapshot}, ids.certs["dave"].scopes)
}

func TestParseAuthFile_UppercaseDigestAndDuplicateScopes(t *testing.T) {
	file := fmt.Sprintf("[[token]]\nname = \"a\"\nsha256 = %q\nscopes = [\"logs\", \"snapshot\", \"logs\"]\n", strings.ToUpper(digestOf(aliceToken)))
	ids, err := ParseAuthFile([]byte(file))
	require.NoError(t, err)
	assert.Equal(t, []Scope{ScopeLogs, ScopeSnapshot}, ids.tokens[0].scopes)
	assert.False(t, ids.HasClientCerts())
}

func TestParseAuthFile_Rejects(t *testing.T) {
	d := digestOf(aliceToken)
	token := func(name, sha, scopes, extra string) string {
		return fmt.Sprintf("[[token]]\nname = %q\nsha256 = %q\nscopes = %s\n%s\n", name, sha, scopes, extra)
	}
	cases := map[string]struct {
		file string
		want string
	}{
		"unknown scope":     {token("a", d, `["snapshot", "admin"]`, ""), `token "a": unknown scope "admin"`},
		"empty scopes":      {token("a", d, `[]`, ""), `token "a": scopes must not be empty`},
		"missing scopes":    {fmt.Sprintf("[[token]]\nname = \"a\"\nsha256 = %q\n", d), `token "a": scopes must not be empty`},
		"duplicate name":    {token("a", d, `["snapshot"]`, "") + token("a", digestOf(bobToken), `["snapshot"]`, ""), `token "a": duplicate name`},
		"duplicate digest":  {token("a", d, `["snapshot"]`, "") + token("b", d, `["snapshot"]`, ""), `token "b": same sha256 as token "a"`},
		"short digest":      {token("a", d[:62], `["snapshot"]`, ""), `token "a": sha256 must be 64 hexadecimal characters`},
		"non-hex digest":    {token("a", "zz"+d[2:], `["snapshot"]`, ""), `token "a": sha256 must be 64 hexadecimal characters`},
		"raw token":         {token("a", aliceToken, `["snapshot"]`, ""), `token "a": sha256 must be 64 hexadecimal characters`},
		"empty name":        {token("", d, `["snapshot"]`, ""), `token #1: name: must be 1 to 64 characters`},
		"long name":         {token(strings.Repeat("n", 65), d, `["snapshot"]`, ""), `token #1: name: must be 1 to 64 characters`},
		"bad name":          {token("al ice", d, `["snapshot"]`, ""), `token #1: name: "al ice": only letters`},
		"control name":      {token("a\x1b[31m", d, `["snapshot"]`, ""), `token #1: name:`},
		"local datetime":    {token("a", d, `["snapshot"]`, "expires = 2026-12-31T00:00:00"), `token "a": expires needs a UTC offset`},
		"local date":        {token("a", d, `["snapshot"]`, "expires = 2026-12-31"), `token "a": expires needs a UTC offset`},
		"string expiry":     {token("a", d, `["snapshot"]`, `expires = "2026-12-31T00:00:00Z"`), `invalid TOML`},
		"unknown key":       {token("a", d, `["snapshot"]`, `scope = ["logs"]`), `unknown key(s): token.scope`},
		"singular table":    {"[token]\nname = \"a\"\n", `invalid TOML`},
		"cert unknown key":  {"[[client_cert]]\ncn = \"x\"\nscopes = [\"logs\"]\nname = \"x\"\n", `unknown key(s): client_cert.name`},
		"cert empty cn":     {"[[client_cert]]\nscopes = [\"logs\"]\n", `client_cert #1: cn must be non-empty`},
		"cert control cn":   {"[[client_cert]]\ncn = \"x\\u0007\"\nscopes = [\"logs\"]\n", `client_cert #1: cn must be non-empty and free of control characters`},
		"cert duplicate cn": {"[[client_cert]]\ncn = \"x\"\nscopes = [\"logs\"]\n[[client_cert]]\ncn = \"x\"\nscopes = [\"logs\"]\n", `client_cert "x": duplicate cn`},
		"cert bad scope":    {"[[client_cert]]\ncn = \"x\"\nscopes = [\"root\"]\n", `client_cert "x": unknown scope "root"`},
		"empty file":        {"# nothing yet\n", `nobody could connect`},
		"wrong type":        {"[[token]]\nname = \"a\"\nsha256 = 12\n", `invalid TOML: a value does not have the expected type`},
		"syntax error":      {"[[token]]\nname = \"a\"\nsha256 = \"" + d + "\n", `invalid TOML at line 3`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ids, err := ParseAuthFile([]byte(tc.file))
			require.Error(t, err)
			assert.Nil(t, ids)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), d, "errors never echo a digest")
			assert.NotContains(t, err.Error(), d[:62])
			assert.NotContains(t, err.Error(), aliceToken)
		})
	}
}

func TestLoadAuthFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.toml")
	require.NoError(t, os.WriteFile(path, []byte(testAuthFile()), 0o600))
	ids, err := LoadAuthFile(path)
	require.NoError(t, err)
	assert.Len(t, ids.tokens, 3)

	_, err = LoadAuthFile(filepath.Join(dir, "missing.toml"))
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, os.WriteFile(path, []byte("[[token]]\n"), 0o600))
	_, err = LoadAuthFile(path)
	require.ErrorContains(t, err, "remote auth file "+path+": token #1")
}

func TestMiddleware_ValidToken(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	rec := h.do(RouteStream, "192.0.2.1:5000", bearer(aliceToken))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "alice||certificates,config,logs,snapshot", rec.Body.String())

	rec = h.do(RouteInfo, "192.0.2.1:5000", map[string][]string{"Authorization": {"bearer " + bobToken}})
	require.Equal(t, http.StatusOK, rec.Code, "the scheme is case-insensitive")
	assert.Equal(t, "bob||snapshot", rec.Body.String())

	assert.Empty(t, h.auditRecords(t), "a success is not an auth event; the session events come from the server")
}

func TestMiddleware_Unauthorized(t *testing.T) {
	cases := map[string]struct {
		headers map[string][]string
		reason  DenyReason
	}{
		"missing":             {nil, DenyMissing},
		"invalid":             {bearer("ember_rt_nope"), DenyInvalid},
		"basic scheme":        {map[string][]string{"Authorization": {"Basic YWxpY2U6c2VjcmV0"}}, DenyInvalid},
		"token as basic":      {map[string][]string{"Authorization": {"Basic " + aliceToken}}, DenyInvalid},
		"no scheme":           {map[string][]string{"Authorization": {aliceToken}}, DenyInvalid},
		"empty bearer":        {map[string][]string{"Authorization": {"Bearer "}}, DenyInvalid},
		"empty header":        {map[string][]string{"Authorization": {""}}, DenyInvalid},
		"prefix of token":     {bearer(aliceToken[:len(aliceToken)-1]), DenyInvalid},
		"token plus a byte":   {bearer(aliceToken + "x"), DenyInvalid},
		"digest as token":     {bearer(digestOf(aliceToken)), DenyInvalid},
		"two headers":         {map[string][]string{"Authorization": {"Bearer " + aliceToken, "Bearer " + bobToken}}, DenyInvalid},
		"expired":             {bearer(carolToken), DenyExpired},
		"trailing whitespace": {bearer(aliceToken + " "), DenyInvalid},
	}

	var bodies []string
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newAuthHarness(t, testAuthFile())
			rec := h.do(RouteStream, "192.0.2.7:4000", tc.headers)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, `Bearer realm="ember-remote"`, rec.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			bodies = append(bodies, rec.Body.String())

			for _, word := range []string{"missing", "invalid", "expired", "cert", "scope", "rate", "alice", "carol"} {
				assert.NotContains(t, strings.ToLower(rec.Body.String()), word, "the reason stays in the audit log")
			}

			records := h.auditRecords(t)
			require.Len(t, records, 1)
			assert.Equal(t, AuditAuthDenied, records[0]["msg"])
			assert.Equal(t, string(tc.reason), records[0]["reason"])
			assert.Equal(t, "192.0.2.7:4000", records[0]["remote_addr"])
			if tc.reason == DenyExpired {
				assert.Equal(t, "carol", records[0]["identity"], "an expired token still names its owner")
			} else {
				assert.Empty(t, records[0]["identity"])
			}
		})
	}
	for _, b := range bodies {
		assert.JSONEq(t, `{"error":"unauthorized"}`, b)
		assert.Equal(t, bodies[0], b, "every 401 is byte-identical")
	}
}

func TestMiddleware_ExpiryIsExclusive(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	h.clock.t = time.Date(2026, 9, 24, 23, 59, 59, 0, time.UTC)
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "192.0.2.1:1", bearer(carolToken)).Code, "valid until its expiry")
	h.clock.Advance(time.Second)
	assert.Equal(t, http.StatusUnauthorized, h.do(RouteStream, "192.0.2.1:1", bearer(carolToken)).Code, "refused from the expiry on")
}

func TestMiddleware_RouteScopeTable(t *testing.T) {
	var file strings.Builder
	tokens := map[Scope]string{}
	for i, s := range knownScopes {
		tok := fmt.Sprintf("ember_rt_scope%d_%s", i, s)
		tokens[s] = tok
		fmt.Fprintf(&file, "[[token]]\nname = %q\nsha256 = %q\nscopes = [%q]\n", "only-"+string(s), digestOf(tok), s)
	}
	h := newAuthHarness(t, file.String())

	for route, required := range routeScopes {
		for _, held := range knownScopes {
			t.Run(route+"/"+string(held), func(t *testing.T) {
				rec := h.do(route, "192.0.2.2:1", bearer(tokens[held]))
				if required == "" || required == held {
					assert.Equal(t, http.StatusOK, rec.Code)
					return
				}
				require.Equal(t, http.StatusForbidden, rec.Code)
				resp, err := DecodeErrorResponse(rec.Body.Bytes())
				require.NoError(t, err)
				assert.Equal(t, fmt.Sprintf("your identity lacks the %q scope", required), resp.Error)
			})
		}
	}

	assert.Equal(t, Scope(""), routeScopes[RouteInfo], "the handshake needs authentication only")
	assert.Equal(t, ScopeSnapshot, routeScopes[RouteStream])
	assert.Equal(t, ScopeConfig, routeScopes[RouteConfig])
	assert.Equal(t, ScopeCertificates, routeScopes[RouteCertificates])
}

func TestMiddleware_EveryRouteHasAScopeEntry(t *testing.T) {
	for _, route := range []string{RouteInfo, RouteStream, RouteConfig, RouteCertificates} {
		_, ok := routeScopes[route]
		assert.True(t, ok, route)
	}
	assert.Len(t, routeScopes, 4, "a route added to the table needs a constant and a row above")
}

func TestMiddleware_UnknownPath(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	for _, path := range []string{"/remote/v1/", "/remote/v1/admin", "/remote/v2/info", "/metrics", "/remote/v1/info/"} {
		assert.Equal(t, http.StatusUnauthorized, h.do(path, "192.0.2.3:1", nil).Code, "unauthenticated callers learn nothing about %s", path)
		rec := h.do(path, "192.0.2.3:1", bearer(aliceToken))
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
		assert.JSONEq(t, `{"error":"not found"}`, rec.Body.String())
	}
}

func TestMiddleware_ForbiddenIsAuditedButNotAFailure(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	for range 2 * defaultMaxFailures {
		require.Equal(t, http.StatusForbidden, h.do(RouteConfig, "192.0.2.4:1", bearer(bobToken)).Code)
	}
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "192.0.2.4:1", bearer(bobToken)).Code, "403s do not feed the limiter")

	records := h.auditRecords(t)
	require.Len(t, records, 2*defaultMaxFailures)
	assert.Equal(t, string(DenyScope), records[0]["reason"])
	assert.Equal(t, "bob", records[0]["identity"])
}

func TestMiddleware_RateLimit(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	for i := range defaultMaxFailures {
		require.Equal(t, http.StatusUnauthorized, h.do(RouteStream, "198.51.100.9:1000", bearer("wrong")).Code, "failure %d", i+1)
	}

	rec := h.do(RouteStream, "198.51.100.9:2000", bearer(aliceToken))
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "blocked even with a valid token, from another port")
	assert.Equal(t, "60", rec.Header().Get("Retry-After"))
	assert.JSONEq(t, `{"error":"too many failed authentication attempts"}`, rec.Body.String())
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "198.51.100.10:1", bearer(aliceToken)).Code, "other sources are unaffected")

	h.clock.Advance(59*time.Second + 500*time.Millisecond)
	rec = h.do(RouteStream, "198.51.100.9:1", bearer(aliceToken))
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"), "rounded up, never 0")

	h.clock.Advance(time.Second)
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "198.51.100.9:1", bearer(aliceToken)).Code)

	var limited []map[string]any
	for _, r := range h.auditRecords(t) {
		if r["reason"] == string(DenyRateLimited) {
			limited = append(limited, r)
		}
	}
	require.Len(t, limited, 1, "audited when the block starts, not on every 429")
	assert.Equal(t, "198.51.100.9", limited[0]["source"])
	assert.InDelta(t, defaultMaxFailures, limited[0]["failures"], 0)
}

func TestNoSecretReachesTheLogs(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	for _, tok := range []string{aliceToken, bobToken, carolToken, "ember_rt_wrong", aliceToken[:20]} {
		h.do(RouteStream, "192.0.2.5:1", bearer(tok))
		h.do(RouteConfig, "192.0.2.5:1", bearer(tok))
		h.do(RouteStream, "192.0.2.5:1", map[string][]string{"Authorization": {"Basic " + tok}})
	}
	for range defaultMaxFailures {
		h.do(RouteStream, "192.0.2.6:1", bearer(aliceToken+"x"))
	}
	h.do(RouteStream, "192.0.2.6:1", bearer(aliceToken))

	path := filepath.Join(t.TempDir(), "auth.toml")
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(testAuthFile(), `"config"`, `"admin"`, 1)), 0o600))
	err := h.auth.ReloadFile(path)
	require.Error(t, err)
	slog.New(slog.NewJSONHandler(h.logs, nil)).Error("reload failed", "err", err)

	out := h.logs.String()
	require.NotEmpty(t, out)
	for _, tok := range []string{aliceToken, bobToken, carolToken} {
		assert.NotContains(t, out, tok)
		assert.NotContains(t, out, strings.TrimPrefix(tok, "ember_rt_")[:16], "not even part of a token")
		assert.NotContains(t, out, digestOf(tok))
		assert.NotContains(t, out, digestOf(tok)[:32], "not even half a digest")
	}
}

func TestReloadFile(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	path := filepath.Join(t.TempDir(), "auth.toml")

	next := fmt.Sprintf("[[token]]\nname = \"bob\"\nsha256 = %q\nscopes = [\"snapshot\", \"logs\"]\n", digestOf(bobToken))
	require.NoError(t, os.WriteFile(path, []byte(next), 0o600))
	require.NoError(t, h.auth.ReloadFile(path))
	assert.Equal(t, http.StatusUnauthorized, h.do(RouteStream, "192.0.2.8:1", bearer(aliceToken)).Code)
	assert.Equal(t, "bob||logs,snapshot", h.do(RouteStream, "192.0.2.8:1", bearer(bobToken)).Body.String())

	require.NoError(t, os.WriteFile(path, []byte("[[token]]\nname = \"x\"\n"), 0o600))
	require.Error(t, h.auth.ReloadFile(path))
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "192.0.2.8:1", bearer(bobToken)).Code)

	require.Error(t, h.auth.ReloadFile(filepath.Join(t.TempDir(), "gone.toml")))
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "192.0.2.8:1", bearer(bobToken)).Code)
}

func TestReloadFile_ConcurrentWithRequests(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	path := filepath.Join(t.TempDir(), "auth.toml")
	require.NoError(t, os.WriteFile(path, []byte(testAuthFile()), 0o600))

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				if code := h.do(RouteStream, "192.0.2.9:1", bearer(aliceToken)).Code; code != http.StatusOK {
					t.Errorf("got %d during a reload", code)
				}
			}
		})
	}
	for range 20 {
		require.NoError(t, h.auth.ReloadFile(path))
	}
	wg.Wait()
}

func TestRevalidate(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	ids := h.auth.ids.Load()
	bob, reason := ids.authenticate(requestWith(bearer(bobToken)), h.clock.Now())
	require.Empty(t, reason)

	got, ok := h.auth.Revalidate(bob)
	require.True(t, ok)
	assert.Equal(t, bob, got)

	swap := func(file string) {
		t.Helper()
		next, err := ParseAuthFile([]byte(file))
		require.NoError(t, err)
		h.auth.ids.Store(next)
	}

	swap(fmt.Sprintf("[[token]]\nname = \"bob\"\nsha256 = %q\nscopes = [\"logs\", \"snapshot\"]\n", digestOf(bobToken)))
	got, ok = h.auth.Revalidate(bob)
	require.True(t, ok)
	assert.Equal(t, []Scope{ScopeLogs, ScopeSnapshot}, got.Scopes, "scopes follow the file")

	swap(fmt.Sprintf("[[token]]\nname = \"bob\"\nsha256 = %q\nscopes = [\"snapshot\"]\n", digestOf(aliceToken)))
	_, ok = h.auth.Revalidate(bob)
	assert.False(t, ok, "a token rotated under the same name revokes the old one")

	swap(fmt.Sprintf("[[token]]\nname = \"robert\"\nsha256 = %q\nscopes = [\"snapshot\"]\n", digestOf(bobToken)))
	_, ok = h.auth.Revalidate(bob)
	assert.False(t, ok, "a renamed token is another identity")

	swap(fmt.Sprintf("[[token]]\nname = \"bob\"\nsha256 = %q\nscopes = [\"snapshot\"]\nexpires = 2026-09-25T12:00:00Z\n", digestOf(bobToken)))
	_, ok = h.auth.Revalidate(bob)
	assert.False(t, ok, "expired since the session opened")
}

func TestRevalidate_CertIdentity(t *testing.T) {
	ids, err := ParseAuthFile([]byte(testAuthFile()))
	require.NoError(t, err)
	dave := Identity{Name: "dave", ClientCN: "dave", Scopes: []Scope{ScopeSnapshot}, cred: credential{cn: "dave"}}

	got, ok := ids.revalidate(dave, fixtureTime)
	require.True(t, ok)
	assert.Equal(t, []Scope{ScopeLogs, ScopeSnapshot}, got.Scopes)

	others, err := ParseAuthFile([]byte("[[client_cert]]\ncn = \"erin\"\nscopes = [\"snapshot\"]\n"))
	require.NoError(t, err)
	_, ok = others.revalidate(dave, fixtureTime)
	assert.False(t, ok)
}

func requestWith(headers map[string][]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, RouteStream, nil)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req
}

func TestAuthenticate_IgnoresUnverifiedCertificates(t *testing.T) {
	ids, err := ParseAuthFile([]byte(testAuthFile()))
	require.NoError(t, err)
	req := requestWith(nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "dave"}}}}
	_, reason := ids.authenticate(req, fixtureTime)
	assert.Equal(t, DenyMissing, reason, "a CN counts only once the chain was verified")
}

func TestIdentityFrom_Absent(t *testing.T) {
	_, ok := IdentityFrom(httptest.NewRequest(http.MethodGet, "/", nil).Context())
	assert.False(t, ok)
}

type testPKI struct {
	caPool *x509.CertPool
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &testPKI{caPool: pool, ca: ca, caKey: key}
}

func (p *testPKI) clientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestMiddleware_MutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	h := newAuthHarness(t, testAuthFile())
	srv := httptest.NewUnstartedServer(h.handler)
	// IfGiven lets one server cover the no-certificate case; the daemon will require one.
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pki.caPool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	get := func(cert *tls.Certificate, token string) (int, string) {
		t.Helper()
		tr := srv.Client().Transport.(*http.Transport).Clone()
		if cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, srv.URL+RouteStream, nil)
		require.NoError(t, err)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := (&http.Client{Transport: tr}).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(body)
	}

	dave := pki.clientCert(t, "dave")
	code, body := get(&dave, "")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "dave|dave|logs,snapshot", body, "a declared CN is the identity")

	mallory := pki.clientCert(t, "mallory")
	code, _ = get(&mallory, "")
	assert.Equal(t, http.StatusUnauthorized, code, "an undeclared CN is refused")

	code, body = get(&dave, aliceToken)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "alice|dave|certificates,config,logs,snapshot", body, "a token decides the identity; the CN is still recorded")

	code, _ = get(&dave, "ember_rt_wrong")
	assert.Equal(t, http.StatusUnauthorized, code, "a bad token does not fall back to the certificate")

	code, _ = get(nil, "")
	assert.Equal(t, http.StatusUnauthorized, code)

	var reasons, cns []any
	for _, r := range h.auditRecords(t) {
		reasons = append(reasons, r["reason"])
		cns = append(cns, r["client_cn"])
	}
	assert.Equal(t, []any{"cert", "invalid", "missing"}, reasons)
	assert.Equal(t, []any{"mallory", "dave", ""}, cns, "the verified CN is audited on refusals too")
}

func TestMiddleware_RateLimitGroupsIPv6By64(t *testing.T) {
	h := newAuthHarness(t, testAuthFile())
	for i := range defaultMaxFailures {
		h.do(RouteStream, fmt.Sprintf("[2001:db8::%x]:1", i+1), bearer("wrong"))
	}
	assert.Equal(t, http.StatusTooManyRequests, h.do(RouteStream, "[2001:db8::ffff]:1", bearer(aliceToken)).Code)
	assert.Equal(t, http.StatusOK, h.do(RouteStream, "[2001:db8:0:1::1]:1", bearer(aliceToken)).Code)
}
