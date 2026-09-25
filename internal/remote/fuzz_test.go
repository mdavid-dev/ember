package remote

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func FuzzSSEReader(f *testing.F) {
	f.Add([]byte("id: e:1\nevent: snapshot\ndata: {}\n\n"))
	f.Add([]byte("data: a\r\ndata: b\r\r\n: ping\n\n"))
	f.Add([]byte("\xEF\xBB\xBFdata\n\nid: \x00\nretry: x\n\n"))
	f.Add([]byte("data: " + strings.Repeat("x", 300)))
	f.Add([]byte("\r\r\r\n\n:\n"))

	const bound = 256
	f.Fuzz(func(t *testing.T, input []byte) {
		r := NewReader(bytes.NewReader(input), bound)
		for range len(input) + 1 {
			ev, err := r.Next()
			if err != nil {
				if _, again := r.Next(); again == nil {
					t.Fatal("a failed reader must stay failed")
				}
				return
			}
			if len(ev.Data) > bound {
				t.Fatalf("event of %d bytes over the %d bound", len(ev.Data), bound)
			}
			if ev.Type == "" {
				t.Fatal("dispatched event without a type")
			}
		}
		t.Fatal("more events than input bytes: the reader is not consuming its input")
	})
}

func FuzzDecodeWireSnapshot(f *testing.F) {
	if golden, err := Marshal(fixtureSnapshot()); err == nil {
		f.Add(golden)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"snapshot":{"metrics":{"durationBuckets":[{"upperBound":"+Inf"},{"upperBound":"-Inf"},{"upperBound":1e308}]}}}`))
	f.Add([]byte(`{"snapshot":{"metrics":{"hosts":{"a":null},"workers":{"w":{}}},"threads":{"ThreadDebugStates":[{}]}}}`))
	f.Add([]byte(`{"snapshot":{"metrics":{"hosts":{"a":{"statusCodes":{"x":1}}}}}}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		ws, err := DecodeSnapshot(input)
		if err != nil {
			return
		}
		_ = ws.ToSnapshot()
		if _, err := Marshal(ws); err != nil {
			t.Fatalf("decoded snapshot does not re-encode: %v", err)
		}
	})
}

func FuzzParseAuthFile(f *testing.F) {
	f.Add([]byte(testAuthFile()))
	f.Add([]byte("[[token]]\nname = \"a\"\nsha256 = \"" + digestOf(aliceToken) + "\"\nscopes = [\"snapshot\"]\nexpires = 2026-12-31\n"))
	f.Add([]byte("[[client_cert]]\ncn = \"x\"\nscopes = [\"logs\", \"logs\"]\n"))
	f.Add([]byte("[token]\n"))
	f.Add([]byte("token = 1\n[[client_cert]]\n"))

	f.Fuzz(func(t *testing.T, input []byte) {
		ids, err := ParseAuthFile(input)
		if err != nil {
			if ids != nil {
				t.Fatal("identities returned alongside an error")
			}
			return
		}
		if len(ids.tokens) == 0 && len(ids.certs) == 0 {
			t.Fatal("a valid file grants at least one identity")
		}
		check := func(scopes []Scope) {
			if len(scopes) == 0 {
				t.Fatal("identity without scopes")
			}
			for _, s := range scopes {
				if !slices.Contains(knownScopes, s) {
					t.Fatalf("unknown scope %q accepted", s)
				}
			}
		}
		for _, tok := range ids.tokens {
			check(tok.scopes)
			if validName(tok.name) != nil {
				t.Fatalf("invalid name %q accepted", tok.name)
			}
		}
		for _, c := range ids.certs {
			check(c.scopes)
		}
	})
}
