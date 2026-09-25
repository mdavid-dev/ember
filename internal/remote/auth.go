package remote

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"
)

type Scope string

const (
	ScopeSnapshot     Scope = CapabilitySnapshot
	ScopeLogs         Scope = CapabilityLogs
	ScopeConfig       Scope = CapabilityConfig
	ScopeCertificates Scope = CapabilityCertificates
)

var knownScopes = []Scope{ScopeSnapshot, ScopeLogs, ScopeConfig, ScopeCertificates}

// routeScopes is the one source of the routes the server mounts; "" means authentication only.
var routeScopes = map[string]Scope{
	RouteInfo:         "",
	RouteStream:       ScopeSnapshot,
	RouteConfig:       ScopeConfig,
	RouteCertificates: ScopeCertificates,
}

type Identity struct {
	Name string
	// ClientCN is recorded even when a token decided the identity.
	ClientCN string
	Scopes   []Scope

	// cred lets Revalidate tell a token rotated under the same name from the one in use.
	cred credential
}

type credential struct {
	digest [sha256.Size]byte // token digest; zero for a certificate identity
	cn     string            // [[client_cert]] CN; empty for a token identity
}

func (id Identity) Has(s Scope) bool { return slices.Contains(id.Scopes, s) }

func (id Identity) ScopeNames() []string {
	names := make([]string, len(id.Scopes))
	for i, s := range id.Scopes {
		names[i] = string(s)
	}
	return names
}

// Identities is immutable, so a reload swaps the whole set atomically.
type Identities struct {
	tokens []tokenIdentity
	certs  map[string]certIdentity
}

type tokenIdentity struct {
	name    string
	digest  [sha256.Size]byte
	scopes  []Scope
	expires time.Time // zero: never
}

type certIdentity struct {
	cn     string
	scopes []Scope
}

func (ids *Identities) HasClientCerts() bool { return len(ids.certs) > 0 }

type authFile struct {
	Token []struct {
		Name    string     `toml:"name"`
		SHA256  string     `toml:"sha256"`
		Scopes  []string   `toml:"scopes"`
		Expires tomlExpiry `toml:"expires"`
	} `toml:"token"`
	ClientCert []struct {
		CN     string   `toml:"cn"`
		Scopes []string `toml:"scopes"`
	} `toml:"client_cert"`
}

func LoadAuthFile(path string) (*Identities, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("remote auth file: %w", err)
	}
	ids, err := ParseAuthFile(data)
	if err != nil {
		return nil, fmt.Errorf("remote auth file %s: %w", path, err)
	}
	return ids, nil
}

// ParseAuthFile fails on anything doubtful rather than skip it: a typo must not
// grant or deny access silently. Errors name the entry, never a digest.
func ParseAuthFile(data []byte) (*Identities, error) {
	var f authFile
	md, err := toml.Decode(string(data), &f)
	if err != nil {
		// A TOML error can quote the offending line, digest included.
		var pe toml.ParseError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("invalid TOML at line %d", pe.Position.Line)
		}
		return nil, errors.New("invalid TOML: a value does not have the expected type")
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown key(s): %s", strings.Join(keys, ", "))
	}

	ids := &Identities{certs: make(map[string]certIdentity)}
	names := make(map[string]bool)
	for i, t := range f.Token {
		label := fmt.Sprintf("token #%d", i+1)
		if err := validName(t.Name); err != nil {
			return nil, fmt.Errorf("%s: name: %w", label, err)
		}
		label = fmt.Sprintf("token %q", t.Name)
		if names[t.Name] {
			return nil, fmt.Errorf("%s: duplicate name", label)
		}
		names[t.Name] = true

		raw, err := hex.DecodeString(t.SHA256)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("%s: sha256 must be %d hexadecimal characters", label, 2*sha256.Size)
		}
		var digest [sha256.Size]byte
		copy(digest[:], raw)
		for _, other := range ids.tokens {
			if other.digest == digest {
				return nil, fmt.Errorf("%s: same sha256 as token %q", label, other.name)
			}
		}

		scopes, err := parseScopes(t.Scopes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if t.Expires.local {
			return nil, fmt.Errorf("%s: expires needs a UTC offset (e.g. 2026-12-31T00:00:00Z)", label)
		}
		ids.tokens = append(ids.tokens, tokenIdentity{name: t.Name, digest: digest, scopes: scopes, expires: t.Expires.t})
	}

	for i, c := range f.ClientCert {
		if c.CN == "" || strings.ContainsFunc(c.CN, unicode.IsControl) {
			return nil, fmt.Errorf("client_cert #%d: cn must be non-empty and free of control characters", i+1)
		}
		label := fmt.Sprintf("client_cert %q", c.CN)
		if _, dup := ids.certs[c.CN]; dup {
			return nil, fmt.Errorf("%s: duplicate cn", label)
		}
		scopes, err := parseScopes(c.Scopes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		ids.certs[c.CN] = certIdentity{cn: c.CN, scopes: scopes}
	}

	if len(ids.tokens) == 0 && len(ids.certs) == 0 {
		return nil, errors.New("no [[token]] or [[client_cert]] entry: nobody could connect")
	}
	return ids, nil
}

// validName keeps names safe in a log line, a terminal badge and a header.
func validName(name string) error {
	if name == "" || len(name) > 64 {
		return errors.New("must be 1 to 64 characters")
	}
	if strings.IndexFunc(name, func(r rune) bool { return !nameRune(r) }) >= 0 {
		return fmt.Errorf("%q: only letters, digits and . _ @ - are allowed", name)
	}
	return nil
}

func nameRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._@-", r)
}

func parseScopes(in []string) ([]Scope, error) {
	if len(in) == 0 {
		return nil, errors.New("scopes must not be empty")
	}
	out := make([]Scope, 0, len(in))
	for _, s := range in {
		if !slices.Contains(knownScopes, Scope(s)) {
			return nil, fmt.Errorf("unknown scope %q (known: snapshot, logs, config, certificates)", s)
		}
		if !slices.Contains(out, Scope(s)) {
			out = append(out, Scope(s))
		}
	}
	slices.Sort(out)
	return out, nil
}

// tomlExpiry spots TOML local date-times, whose expiry would follow the daemon's
// timezone. Only UnmarshalTOML sees the decoder's zone marker; time.Time loses it.
type tomlExpiry struct {
	t     time.Time
	local bool
}

func (e *tomlExpiry) UnmarshalTOML(v any) error {
	t, ok := v.(time.Time)
	if !ok {
		return errors.New("expires must be a date-time")
	}
	switch t.Location().String() {
	case "datetime-local", "date-local", "time-local":
		e.local = true
	}
	e.t = t
	return nil
}

// authenticate never falls back to the certificate when a presented token is bad.
func (ids *Identities) authenticate(r *http.Request, now time.Time) (Identity, DenyReason) {
	cn := verifiedCN(r)

	if values := r.Header.Values("Authorization"); len(values) > 0 {
		token, ok := bearerToken(values)
		if !ok {
			return Identity{}, DenyInvalid
		}
		digest := sha256.Sum256([]byte(token))
		// No early exit: the time taken must not depend on which entry matched.
		found := -1
		for i := range ids.tokens {
			if subtle.ConstantTimeCompare(digest[:], ids.tokens[i].digest[:]) == 1 {
				found = i
			}
		}
		if found < 0 {
			return Identity{}, DenyInvalid
		}
		t := ids.tokens[found]
		if !t.expires.IsZero() && !now.Before(t.expires) {
			return Identity{}, DenyExpired
		}
		return Identity{Name: t.name, ClientCN: cn, Scopes: t.scopes, cred: credential{digest: t.digest}}, ""
	}

	if cn != "" {
		c, ok := ids.certs[cn]
		if !ok {
			return Identity{}, DenyCert
		}
		return Identity{Name: c.cn, ClientCN: cn, Scopes: c.scopes, cred: credential{cn: c.cn}}, ""
	}
	return Identity{}, DenyMissing
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

func verifiedCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return ""
	}
	return r.TLS.VerifiedChains[0][0].Subject.CommonName
}

// revalidate returns id with its current scopes; a rotated, renamed or expired token is revoked.
func (ids *Identities) revalidate(id Identity, now time.Time) (Identity, bool) {
	if id.cred.cn != "" {
		c, ok := ids.certs[id.cred.cn]
		if !ok {
			return Identity{}, false
		}
		id.Scopes = c.scopes
		return id, true
	}
	for _, t := range ids.tokens {
		if t.digest == id.cred.digest && t.name == id.Name {
			if !t.expires.IsZero() && !now.Before(t.expires) {
				return Identity{}, false
			}
			id.Scopes = t.scopes
			return id, true
		}
	}
	return Identity{}, false
}

type Authenticator struct {
	ids     atomic.Pointer[Identities]
	limiter *RateLimiter
	audit   *Auditor
	now     func() time.Time
}

func NewAuthenticator(ids *Identities, limiter *RateLimiter, audit *Auditor, now func() time.Time) *Authenticator {
	if now == nil {
		now = time.Now
	}
	a := &Authenticator{limiter: limiter, audit: audit, now: now}
	a.ids.Store(ids)
	return a
}

// ReloadFile keeps the current identities when the new file is invalid.
func (a *Authenticator) ReloadFile(path string) error {
	ids, err := LoadAuthFile(path)
	if err != nil {
		return err
	}
	a.ids.Store(ids)
	return nil
}

func (a *Authenticator) Revalidate(id Identity) (Identity, bool) {
	return a.ids.Load().revalidate(id, a.now())
}

type identityKey struct{}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// Middleware answers every 401 with the same body: the reason goes to the audit log only.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := clientIP(r.RemoteAddr)
		denied := func(reason DenyReason) {
			a.audit.AuthDenied(r.Context(), AuthDeniedEvent{RemoteAddr: r.RemoteAddr, Reason: reason, UserAgent: r.UserAgent()})
		}

		if ok, wait := a.limiter.Allow(source); !ok {
			denied(DenyRateLimited)
			w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
			writeError(w, http.StatusTooManyRequests, ErrorResponse{Error: "too many failed authentication attempts"})
			return
		}

		id, reason := a.ids.Load().authenticate(r, a.now())
		if reason != "" {
			a.limiter.Fail(source)
			denied(reason)
			w.Header().Set("WWW-Authenticate", `Bearer realm="ember-remote"`)
			writeError(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}

		required, known := routeScopes[r.URL.Path]
		if !known {
			writeError(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
			return
		}
		if required != "" && !id.Has(required) {
			denied(DenyScope)
			writeError(w, http.StatusForbidden, ErrorResponse{Error: fmt.Sprintf("your identity lacks the %q scope", required)})
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().WithZone("").String()
	}
	return host
}

func writeError(w http.ResponseWriter, status int, body ErrorResponse) {
	// An ErrorResponse always encodes.
	data, _ := Marshal(body)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
