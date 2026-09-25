package remote

import (
	"bytes"
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
