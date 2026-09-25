package remote

import (
	"bytes"
	"errors"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/pkg/metrics"
)

// lockedBuffer is written by handler goroutines and read by the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newTestBroadcaster(names ...string) (*Broadcaster, *lockedBuffer) {
	logs := &lockedBuffer{}
	specs := make([]InstanceSpec, len(names))
	for i, n := range names {
		specs[i] = InstanceSpec{Name: n, Interval: time.Second}
	}
	return NewBroadcaster(specs, slog.New(slog.NewJSONHandler(logs, nil))), logs
}

func snapWithThreads(n float64) *metrics.Snapshot {
	return &metrics.Snapshot{FetchedAt: fixtureTime, HasFrankenPHP: true, Metrics: metrics.MetricsSnapshot{TotalThreads: n}}
}

// within fails the test, instead of hanging the suite, when fn blocks.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		require.FailNow(t, "blocked", "still running after %s", d)
	}
}

func waitReady(t *testing.T, sub *Subscription) {
	t.Helper()
	select {
	case <-sub.Ready():
	case <-time.After(5 * time.Second):
		require.FailNow(t, "subscription never woke up")
	}
}

func decodeEvent(t *testing.T, ev *event) WireSnapshot {
	t.Helper()
	require.Equal(t, EventSnapshot, ev.typ)
	ws, err := DecodeSnapshot(ev.data)
	require.NoError(t, err)
	return ws
}

func TestBroadcaster_FrozenSubscriberNeverSlowsPublish(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	frozen, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)

	within(t, 2*time.Second, func() {
		for i := range 100 {
			b.PublishSnapshot(DefaultInstance, snapWithThreads(float64(i)))
			b.PublishFailure(DefaultInstance, errors.New("down"))
		}
	})

	evs := frozen.Take()
	require.Len(t, evs, 2, "latest wins: one pending event per kind, no queue")
	assert.Equal(t, 99.0, decodeEvent(t, evs[0]).Snapshot.Metrics.TotalThreads)
	assert.Equal(t, EventStatus, evs[1].typ)
	assert.Empty(t, frozen.Take(), "a taken event is not sent twice")
}

func TestBroadcaster_TakeKeepsPublishOrder(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)

	b.PublishFailure(DefaultInstance, errors.New("connection refused"))
	b.PublishFailure(DefaultInstance, errors.New("still refused"))
	b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	waitReady(t, sub)
	evs := sub.Take()
	require.Len(t, evs, 2, "one pending event per kind; a repeated failure is not a change")
	assert.Equal(t, EventSnapshot, evs[0].typ)
	assert.Equal(t, EventStatus, evs[1].typ)
	assert.Less(t, evs[0].seq, evs[1].seq)

	st, err := DecodeStatus(evs[1].data)
	require.NoError(t, err)
	assert.Equal(t, StateOK, st.State, "the unreachable status was superseded before the take")
}

func TestBroadcaster_StatusTransitions(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)

	b.PublishFailure(DefaultInstance, errors.New("dial tcp: connection refused"))
	evs := sub.Take()
	require.Len(t, evs, 1)
	st, err := DecodeStatus(evs[0].data)
	require.NoError(t, err)
	assert.Equal(t, StateUnreachable, st.State)
	assert.Equal(t, "dial tcp: connection refused", st.Error)
	assert.False(t, st.Since.IsZero())

	b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	evs = sub.Take()
	require.Len(t, evs, 2)
	assert.Equal(t, EventSnapshot, evs[0].typ)
	st, err = DecodeStatus(evs[1].data)
	require.NoError(t, err)
	assert.Equal(t, StateOK, st.State)

	b.PublishSnapshot(DefaultInstance, snapWithThreads(2))
	evs = sub.Take()
	require.Len(t, evs, 1, "no status while nothing changes")
}

func TestBroadcaster_SubscribeStartsFromLastKnown(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	empty, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	select {
	case <-empty.Ready():
		t.Fatal("nothing to send before the first poll")
	default:
	}

	b.PublishSnapshot(DefaultInstance, snapWithThreads(7))
	late, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	waitReady(t, late)
	evs := late.Take()
	require.Len(t, evs, 1, "no status event when the instance is ok")
	assert.Equal(t, 7.0, decodeEvent(t, evs[0]).Snapshot.Metrics.TotalThreads)

	b.PublishFailure(DefaultInstance, errors.New("down"))
	midOutage, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	evs = midOutage.Take()
	require.Len(t, evs, 2, "a client joining mid-outage learns the data is old")
	assert.Equal(t, EventSnapshot, evs[0].typ)
	assert.Equal(t, EventStatus, evs[1].typ)
}

func TestBroadcaster_InstancesAreIsolated(t *testing.T) {
	b, _ := newTestBroadcaster("api", "web")
	api, err := b.Subscribe("api")
	require.NoError(t, err)
	b.PublishSnapshot("web", snapWithThreads(1))
	b.PublishFailure("web", errors.New("down"))
	assert.Empty(t, api.Take())

	_, err = b.Subscribe("nope")
	require.ErrorIs(t, err, errUnknownInstance)
	b.PublishSnapshot("nope", snapWithThreads(1))
	b.PublishFailure("nope", errors.New("x"))
}

func TestBroadcaster_Instances(t *testing.T) {
	b, _ := newTestBroadcaster("api", "web")
	b.PublishSnapshot("web", snapWithThreads(1))
	assert.Equal(t, []InstanceInfo{
		{Name: "api", Interval: Duration(time.Second)},
		{Name: "web", HasFrankenPHP: true, Interval: Duration(time.Second)},
	}, b.Instances())
}

func TestBroadcaster_OversizedSnapshotIsSkippedAndReported(t *testing.T) {
	b, logs := newTestBroadcaster(DefaultInstance)
	b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	sub.Take()

	b.maxEventSize = 64
	for range 5 {
		b.PublishSnapshot(DefaultInstance, snapWithThreads(2))
	}
	evs := sub.Take()
	require.Len(t, evs, 1, "no snapshot over the bound, one stale status")
	st, err := DecodeStatus(evs[0].data)
	require.NoError(t, err)
	assert.Equal(t, StateStale, st.State)
	assert.Equal(t, 1, strings.Count(logs.String(), "over the client event bound"), "logged when it starts, not every poll")

	b.maxEventSize = DefaultMaxEventSize
	b.PublishSnapshot(DefaultInstance, snapWithThreads(3))
	assert.Len(t, sub.Take(), 2)
	assert.Contains(t, logs.String(), "snapshots sent again")
}

func TestBroadcaster_UnencodableSnapshotIsStale(t *testing.T) {
	b, logs := newTestBroadcaster(DefaultInstance)
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	b.PublishSnapshot(DefaultInstance, &metrics.Snapshot{Process: metrics.ProcessMetrics{CPUPercent: math.NaN()}})
	evs := sub.Take()
	require.Len(t, evs, 1)
	assert.Equal(t, EventStatus, evs[0].typ)
	assert.Contains(t, logs.String(), "snapshot not sent")
}

func TestBroadcaster_EventAtTheBoundReachesTheClient(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	assert.Equal(t, DefaultMaxEventSize, b.maxEventSize, "the daemon checks the bound the client reads with")

	snap := snapWithThreads(1)
	data, err := Marshal(NewWireSnapshot(DefaultInstance, snap))
	require.NoError(t, err)
	b.maxEventSize = len(data)
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	b.PublishSnapshot(DefaultInstance, snap)
	evs := sub.Take()
	require.Len(t, evs, 1)

	var wire bytes.Buffer
	_, err = WriteEvent(&wire, Event{ID: b.eventID(evs[0]), Type: evs[0].typ, Data: evs[0].data})
	require.NoError(t, err)
	ev, err := NewReader(&wire, len(data)).Next()
	require.NoError(t, err)
	assert.Equal(t, data, ev.Data)
}

func TestBroadcaster_Close(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	b.Close()
	b.Close()
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Done never closed")
	}

	_, err = b.Subscribe(DefaultInstance)
	require.ErrorIs(t, err, errBroadcasterClosed)
	b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	b.PublishFailure(DefaultInstance, errors.New("x"))
	assert.Empty(t, sub.Take())
	sub.Close()
}

func TestBroadcaster_EventIDsAreMonotone(t *testing.T) {
	b, _ := newTestBroadcaster(DefaultInstance)
	first := b.nextID()
	b.PublishSnapshot(DefaultInstance, snapWithThreads(1))
	sub, err := b.Subscribe(DefaultInstance)
	require.NoError(t, err)
	second := b.eventID(sub.Take()[0])

	e1, s1, ok := ParseEventID(first)
	require.True(t, ok)
	e2, s2, ok := ParseEventID(second)
	require.True(t, ok)
	assert.Equal(t, b.Epoch(), e1)
	assert.Equal(t, e1, e2)
	assert.Less(t, s1, s2)

	other, _ := newTestBroadcaster(DefaultInstance)
	assert.NotEqual(t, b.Epoch(), other.Epoch(), "every daemon start draws a new epoch")
}

func logEntries(n, uriLen int) []WireLogEntry {
	entries := make([]WireLogEntry, n)
	for i := range entries {
		entries[i] = WireLogEntry{Timestamp: fixtureTime, Host: "h", URI: "/" + strings.Repeat("u", uriLen), Status: i}
	}
	return entries
}

func TestEncodeLogBatches_StayWithinBounds(t *testing.T) {
	entries := logEntries(3000, 1000)
	batches := encodeLogBatches(entries, 4)
	require.Greater(t, len(batches), 3)

	var got []WireLogEntry
	for i, data := range batches {
		assert.LessOrEqual(t, len(data), logBatchMaxBytes)
		lb, err := DecodeLogBatch(data)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(lb.Entries), logBatchMaxEntries)
		if i == 0 {
			assert.Equal(t, int64(4), lb.Dropped)
		} else {
			assert.Zero(t, lb.Dropped, "a loss is reported once")
		}
		got = append(got, lb.Entries...)
	}
	assert.Equal(t, entries, got, "order kept, nothing lost or duplicated")
}

func TestEncodeLogBatches_CountBound(t *testing.T) {
	batches := encodeLogBatches(logEntries(logBatchMaxEntries+1, 1), 0)
	require.Len(t, batches, 2)
	lb, err := DecodeLogBatch(batches[1])
	require.NoError(t, err)
	assert.Len(t, lb.Entries, 1)
}

func TestEncodeLogBatches_MatchesMarshal(t *testing.T) {
	entries := logEntries(3, 5)
	batches := encodeLogBatches(entries, 2)
	require.Len(t, batches, 1)
	want, err := Marshal(LogBatch{Entries: entries, Dropped: 2})
	require.NoError(t, err)
	assert.Equal(t, want, batches[0])
}

func TestEncodeLogBatches_OversizedEntryIsCounted(t *testing.T) {
	entries := append(logEntries(1, 1), logEntries(1, logBatchMaxBytes)...)
	entries = append(entries, logEntries(1, 1)...)
	batches := encodeLogBatches(entries, 0)
	require.Len(t, batches, 1)
	lb, err := DecodeLogBatch(batches[0])
	require.NoError(t, err)
	assert.Len(t, lb.Entries, 2)
	assert.Equal(t, int64(1), lb.Dropped)
}

func TestEncodeLogBatches_EdgeCases(t *testing.T) {
	assert.Empty(t, encodeLogBatches(nil, 0))
	batches := encodeLogBatches(nil, 7)
	require.Len(t, batches, 1, "a loss alone is still reported")
	assert.JSONEq(t, `{"entries":[],"dropped":7}`, string(batches[0]))
}

func TestEncodeLogBatches_ThroughTheClientReader(t *testing.T) {
	var wire bytes.Buffer
	for _, data := range encodeLogBatches(logEntries(2000, 2000), 0) {
		_, err := WriteEvent(&wire, Event{Type: EventLogs, Data: data})
		require.NoError(t, err)
	}
	r := NewReader(&wire, 0)
	var n int
	for {
		ev, err := r.Next()
		if err != nil {
			break
		}
		lb, err := DecodeLogBatch(ev.Data)
		require.NoError(t, err)
		n += len(lb.Entries)
	}
	assert.Equal(t, 2000, n)
}
