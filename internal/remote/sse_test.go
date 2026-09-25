package remote

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readAll(t *testing.T, r *Reader) ([]Event, error) {
	t.Helper()
	var events []Event
	for {
		ev, err := r.Next()
		if err != nil {
			return events, err
		}
		events = append(events, ev)
	}
}

func TestWriteEvent_Framing(t *testing.T) {
	var buf bytes.Buffer
	n, err := WriteEvent(&buf, Event{ID: "e:1", Type: EventSnapshot, Data: []byte(`{"a":1}`)})
	require.NoError(t, err)
	assert.Equal(t, "id: e:1\nevent: snapshot\ndata: {\"a\":1}\n\n", buf.String())
	assert.Equal(t, buf.Len(), n)
}

func TestWriteEvent_MultiLineData(t *testing.T) {
	var buf bytes.Buffer
	_, err := WriteEvent(&buf, Event{Data: []byte("one\ntwo\r\nthree\rfour\n")})
	require.NoError(t, err)
	assert.Equal(t, "data: one\ndata: two\ndata: three\ndata: four\ndata: \n\n", buf.String())
}

func TestWriteEvent_EmptyDataStillDispatches(t *testing.T) {
	var buf bytes.Buffer
	_, err := WriteEvent(&buf, Event{Type: "x"})
	require.NoError(t, err)

	ev, err := NewReader(&buf, 0).Next()
	require.NoError(t, err)
	assert.Equal(t, "x", ev.Type)
	assert.Empty(t, ev.Data)
}

func TestWriteEvent_RejectsLineBreaksInHeaders(t *testing.T) {
	for _, ev := range []Event{{ID: "a\nb"}, {ID: "a\rb"}, {ID: "a\x00b"}, {Type: "a\nevent: forged"}} {
		var buf bytes.Buffer
		_, err := WriteEvent(&buf, ev)
		require.Error(t, err, "%+v", ev)
		assert.Zero(t, buf.Len(), "nothing is written for a rejected event")
	}
}

func TestWriteEvent_SingleWrite(t *testing.T) {
	w := &countingWriter{}
	_, err := WriteEvent(w, Event{ID: "e:1", Type: "t", Data: []byte("a\nb\nc")})
	require.NoError(t, err)
	assert.Equal(t, 1, w.writes, "one Write per event, so a write deadline covers it whole")
}

type countingWriter struct {
	bytes.Buffer
	writes int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.Buffer.Write(p)
}

func TestWriteComment(t *testing.T) {
	var buf bytes.Buffer
	n, err := WriteComment(&buf, "ping")
	require.NoError(t, err)
	assert.Equal(t, ": ping\n\n", buf.String())
	assert.Equal(t, 8, n)

	_, err = WriteComment(&buf, "a\nb")
	require.Error(t, err)
}

func TestSSE_RoundTrip(t *testing.T) {
	sent := []Event{
		{ID: "e:1", Type: EventHello, Data: []byte(`{"sessionId":"s"}`)},
		{ID: "e:2", Type: EventSnapshot, Data: []byte("line1\nline2")},
		{ID: "e:3", Type: EventLogs, Data: []byte("  leading spaces survive")},
		{ID: "e:4", Type: EventStatus, Data: []byte("data: looks like a field")},
	}
	var buf bytes.Buffer
	for _, ev := range sent {
		_, err := WriteEvent(&buf, ev)
		require.NoError(t, err)
		_, err = WriteComment(&buf, "ping")
		require.NoError(t, err)
	}

	r := NewReader(&buf, 0)
	got, err := readAll(t, r)
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, sent, got)
	assert.Equal(t, "e:4", r.LastEventID())
}

func TestReader_LineTerminators(t *testing.T) {
	for name, stream := range map[string]string{
		"LF":       "event: a\ndata: x\ndata: y\n\n",
		"CRLF":     "event: a\r\ndata: x\r\ndata: y\r\n\r\n",
		"CR":       "event: a\rdata: x\rdata: y\r\r",
		"mixed":    "event: a\r\ndata: x\rdata: y\n\r\n",
		"no space": "event:a\ndata:x\ndata:y\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readAll(t, NewReader(strings.NewReader(stream), 0))
			require.ErrorIs(t, err, io.EOF)
			require.Len(t, got, 1)
			assert.Equal(t, "a", got[0].Type)
			assert.Equal(t, "x\ny", string(got[0].Data))
		})
	}
}

type crSplitReader struct{ chunks []string }

func (c *crSplitReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	if c.chunks[0] == "" {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}

func TestReader_CRLFSplitAcrossReads(t *testing.T) {
	r := NewReader(&crSplitReader{chunks: []string{"data: a\r", "\ndata: b\r", "\n\r", "\n"}}, 0)
	got, err := readAll(t, r)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 1, "a split \\r\\n must not count as two line breaks")
	assert.Equal(t, "a\nb", string(got[0].Data))
}

func TestReader_OneByteAtATime(t *testing.T) {
	var buf bytes.Buffer
	sent := []Event{
		{ID: "e:1", Type: "a", Data: []byte("x\r\ny")},
		{ID: "e:2", Type: "b", Data: []byte(strings.Repeat("z", 5000))},
	}
	for _, ev := range sent {
		_, err := WriteEvent(&buf, ev)
		require.NoError(t, err)
	}
	stream := strings.ReplaceAll(buf.String(), "\n", "\r\n")

	got, err := readAll(t, NewReader(iotest.OneByteReader(strings.NewReader(stream)), 0))
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 2)
	assert.Equal(t, "x\ny", string(got[0].Data))
	assert.Equal(t, sent[1], got[1])
}

func TestReader_MultipleBlankLinesAndComments(t *testing.T) {
	stream := "\n\n: hello\n\n\ndata: a\n\n\n\n:ping\n\ndata: b\n\n"
	got, err := readAll(t, NewReader(strings.NewReader(stream), 0))
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 2)
	assert.Equal(t, "a", string(got[0].Data))
	assert.Equal(t, "b", string(got[1].Data))
}

func TestReader_DefaultsAndUnknownFields(t *testing.T) {
	stream := "retry: 10\nfoo: bar\ndata\nevent\n\n"
	got, err := readAll(t, NewReader(strings.NewReader(stream), 0))
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 1)
	assert.Equal(t, "message", got[0].Type, "an empty event field falls back to message")
	assert.Empty(t, got[0].Data)
}

func TestReader_EventWithoutDataIsNotDispatched(t *testing.T) {
	stream := "id: e:7\nevent: a\n\ndata: x\n\n"
	r := NewReader(strings.NewReader(stream), 0)
	got, err := readAll(t, r)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 1)
	assert.Equal(t, "message", got[0].Type, "the type of an undispatched event does not leak into the next")
	assert.Equal(t, "e:7", got[0].ID, "an id still counts")
}

func TestReader_IDIsStickyAndNULIgnored(t *testing.T) {
	stream := "id: e:1\ndata: a\n\ndata: b\n\nid: bad\x00id\ndata: c\n\nid\ndata: d\n\n"
	r := NewReader(strings.NewReader(stream), 0)
	got, err := readAll(t, r)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 4)
	assert.Equal(t, "e:1", got[0].ID)
	assert.Equal(t, "e:1", got[1].ID)
	assert.Equal(t, "e:1", got[2].ID, "an id holding NUL is ignored")
	assert.Empty(t, got[3].ID, "an empty id resets it")
	assert.Empty(t, r.LastEventID())
}

func TestReader_StripsLeadingBOM(t *testing.T) {
	got, err := readAll(t, NewReader(strings.NewReader("\xEF\xBB\xBFdata: a\n\n"), 0))
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 1)
	assert.Equal(t, "a", string(got[0].Data))
}

func TestReader_TruncatedStream(t *testing.T) {
	for name, stream := range map[string]string{
		"mid line":  "data: a\n\ndata: b",
		"mid event": "data: a\n\ndata: b\n",
		"id only":   "data: a\n\nid: x\n",
		"mid field": "data: a\n\nevent: x",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readAll(t, NewReader(strings.NewReader(stream), 0))
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			require.Len(t, got, 1, "the incomplete event is discarded")
		})
	}
}

func TestReader_ErrorIsSticky(t *testing.T) {
	r := NewReader(strings.NewReader("data: a"), 0)
	_, err := r.Next()
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = r.Next()
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

// endless makes an unbounded reader hang instead of fail.
type endless byte

func (e endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(e)
	}
	return len(p), nil
}

func TestReader_LineTooLongIsBounded(t *testing.T) {
	r := NewReader(io.MultiReader(strings.NewReader("data: "), endless('x')), 1024)
	_, err := r.Next()
	require.ErrorIs(t, err, ErrEventTooLarge)
	_, err = r.Next()
	require.ErrorIs(t, err, ErrEventTooLarge, "the reader stays failed rather than reporting EOF")
}

func TestReader_EventTooLargeAcrossDataLines(t *testing.T) {
	line := "data: " + strings.Repeat("y", 100) + "\n"
	r := NewReader(io.MultiReader(strings.NewReader(strings.Repeat(line, 11)), endless('\n')), 1024)
	_, err := r.Next()
	require.ErrorIs(t, err, ErrEventTooLarge)
}

func TestReader_EventAtTheBoundIsAccepted(t *testing.T) {
	data := strings.Repeat("y", 1024)
	got, err := readAll(t, NewReader(strings.NewReader("data: "+data+"\n\n"), 1024))
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, got, 1)
	assert.Len(t, got[0].Data, 1024)
}

func TestReader_PropagatesReadErrors(t *testing.T) {
	boom := errors.New("connection reset")
	r := NewReader(io.MultiReader(strings.NewReader("data: a\n\n"), iotest.ErrReader(boom)), 0)
	ev, err := r.Next()
	require.NoError(t, err)
	assert.Equal(t, "a", string(ev.Data))

	_, err = r.Next()
	require.ErrorIs(t, err, boom)
}

func TestReader_ReturnedDataIsNotAliased(t *testing.T) {
	r := NewReader(strings.NewReader("data: first\n\ndata: second\n\n"), 0)
	first, err := r.Next()
	require.NoError(t, err)
	_, err = r.Next()
	require.NoError(t, err)
	assert.Equal(t, "first", string(first.Data), "a later Next must not overwrite an earlier event")
}
