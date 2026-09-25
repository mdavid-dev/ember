package remote

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Server-Sent Events per the WHATWG grammar. retry is ignored: the client paces its reconnects.

const DefaultMaxEventSize = 8 << 20

var ErrEventTooLarge = errors.New("sse: event too large")

type Event struct {
	ID   string
	Type string
	Data []byte
}

// WriteEvent issues a single Write, so a write deadline covers the whole event.
func WriteEvent(w io.Writer, ev Event) (int, error) {
	if strings.ContainsAny(ev.ID, "\r\n\x00") {
		return 0, fmt.Errorf("sse: id %q contains a line break or NUL", ev.ID)
	}
	if strings.ContainsAny(ev.Type, "\r\n") {
		return 0, fmt.Errorf("sse: event type %q contains a line break", ev.Type)
	}

	var buf bytes.Buffer
	buf.Grow(len(ev.Data) + len(ev.ID) + len(ev.Type) + 32)
	if ev.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(ev.ID)
		buf.WriteByte('\n')
	}
	if ev.Type != "" {
		buf.WriteString("event: ")
		buf.WriteString(ev.Type)
		buf.WriteByte('\n')
	}
	data := ev.Data
	for {
		line, rest, found := cutLine(data)
		buf.WriteString("data: ")
		buf.Write(line)
		buf.WriteByte('\n')
		if !found {
			break
		}
		data = rest
	}
	buf.WriteByte('\n')
	return w.Write(buf.Bytes())
}

func WriteComment(w io.Writer, text string) (int, error) {
	if strings.ContainsAny(text, "\r\n") {
		return 0, fmt.Errorf("sse: comment %q contains a line break", text)
	}
	return io.WriteString(w, ": "+text+"\n\n")
}

func cutLine(b []byte) (line, rest []byte, found bool) {
	i := bytes.IndexAny(b, "\r\n")
	if i < 0 {
		return b, nil, false
	}
	if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
		return b[:i], b[i+2:], true
	}
	return b[:i], b[i+1:], true
}

// Reader holds at most about twice its event bound, whatever the input. Its errors are sticky.
type Reader struct {
	sc      *bufio.Scanner
	max     int
	lastID  string
	started bool
	err     error
}

func NewReader(r io.Reader, maxEventSize int) *Reader {
	if maxEventSize <= 0 {
		maxEventSize = DefaultMaxEventSize
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, min(maxEventSize, 64<<10)), maxEventSize+len("data: ")+2)
	sc.Split(scanSSELines)
	return &Reader{sc: sc, max: maxEventSize}
}

var errUnterminated = errors.New("sse: unterminated line")

// scanSSELines waits on a trailing "\r": it may be half of a "\r\n" split across reads.
func scanSSELines(data []byte, atEOF bool) (int, []byte, error) {
	i := bytes.IndexAny(data, "\r\n")
	switch {
	case i < 0:
		if atEOF && len(data) > 0 {
			return 0, nil, errUnterminated
		}
		return 0, nil, nil
	case data[i] == '\n':
		return i + 1, data[:i], nil
	case i+1 < len(data):
		if data[i+1] == '\n' {
			return i + 2, data[:i], nil
		}
		return i + 1, data[:i], nil
	case atEOF:
		return i + 1, data[:i], nil
	default:
		return 0, nil, nil
	}
}

func (r *Reader) LastEventID() string { return r.lastID }

// Next returns io.ErrUnexpectedEOF, not io.EOF, when the stream ends inside an event.
func (r *Reader) Next() (Event, error) {
	if r.err != nil {
		return Event{}, r.err
	}
	var (
		typ     string
		data    []byte
		hasData bool
		pending bool
	)
	for r.sc.Scan() {
		line := r.sc.Bytes()
		if !r.started {
			r.started = true
			line = bytes.TrimPrefix(line, []byte("\xEF\xBB\xBF"))
		}

		if len(line) == 0 {
			if !hasData {
				// An event without data is not dispatched; its id still counts.
				typ, pending = "", false
				continue
			}
			if typ == "" {
				typ = "message"
			}
			return Event{ID: r.lastID, Type: typ, Data: data[:len(data)-1]}, nil
		}
		if line[0] == ':' {
			continue
		}

		pending = true
		field, value, found := bytes.Cut(line, []byte(":"))
		if found {
			value = bytes.TrimPrefix(value, []byte(" "))
		}
		switch string(field) {
		case "event":
			typ = string(value)
		case "data":
			if len(data)+len(value) > r.max {
				r.err = ErrEventTooLarge
				return Event{}, r.err
			}
			data = append(data, value...)
			data = append(data, '\n')
			hasData = true
		case "id":
			if bytes.IndexByte(value, 0) < 0 {
				r.lastID = string(value)
			}
		}
	}

	switch err := r.sc.Err(); {
	case err == nil && pending:
		r.err = io.ErrUnexpectedEOF
	case err == nil:
		r.err = io.EOF
	case errors.Is(err, errUnterminated):
		r.err = io.ErrUnexpectedEOF
	case errors.Is(err, bufio.ErrTooLong):
		r.err = ErrEventTooLarge
	default:
		r.err = fmt.Errorf("sse: read: %w", err)
	}
	return Event{}, r.err
}
