package remote

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/alexandre-daubois/ember/pkg/metrics"
)

// Log batches stay far below DefaultMaxEventSize, the bound a client reads with.
const (
	logBatchMaxEntries = 500
	logBatchMaxBytes   = 1 << 20
)

var (
	errBroadcasterClosed = errors.New("remote: broadcaster closed")
	errUnknownInstance   = errors.New("remote: unknown instance")
)

type InstanceSpec struct {
	Name     string
	Interval time.Duration
}

// Broadcaster fans the daemon's polls out to the stream subscribers. Publish
// never waits on a subscriber: each one holds only the latest pending event
// of each kind, which the next publish replaces.
type Broadcaster struct {
	epoch        string
	log          *slog.Logger
	maxEventSize int
	now          func() time.Time

	mu     sync.Mutex
	seq    uint64
	feeds  map[string]*feed
	order  []string
	subs   map[*Subscription]struct{}
	closed bool
	done   chan struct{}
}

type feed struct {
	spec          InstanceSpec
	hasFrankenPHP bool
	snapshot      *event
	status        Status
	statusEvent   *event
}

type event struct {
	seq  uint64
	typ  string
	data []byte
}

// NewBroadcaster takes the instances under their wire names. A nil log
// discards the daemon-side errors.
func NewBroadcaster(instances []InstanceSpec, log *slog.Logger) *Broadcaster {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	b := &Broadcaster{
		epoch:        rand.Text(),
		log:          log,
		maxEventSize: DefaultMaxEventSize,
		now:          time.Now,
		feeds:        make(map[string]*feed, len(instances)),
		subs:         make(map[*Subscription]struct{}),
		done:         make(chan struct{}),
	}
	for _, spec := range instances {
		b.order = append(b.order, spec.Name)
		b.feeds[spec.Name] = &feed{spec: spec, status: Status{State: StateOK, Since: b.now()}}
	}
	return b
}

func (b *Broadcaster) Epoch() string { return b.epoch }

func (b *Broadcaster) Instances() []InstanceInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]InstanceInfo, 0, len(b.order))
	for _, name := range b.order {
		f := b.feeds[name]
		out = append(out, InstanceInfo{Name: name, HasFrankenPHP: f.hasFrankenPHP, Interval: Duration(f.spec.Interval)})
	}
	return out
}

// PublishSnapshot encodes s before returning: the caller's state shares
// pointers with it and is overwritten by the next poll.
func (b *Broadcaster) PublishSnapshot(instance string, s *metrics.Snapshot) {
	data, err := Marshal(NewWireSnapshot(instance, s))
	tooLarge := err == nil && len(data) > b.maxEventSize

	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.feeds[instance]
	if !ok || b.closed {
		return
	}
	switch {
	case err != nil:
		b.log.Error("remote: snapshot not sent", "instance", instance, "err", err)
		b.setStatus(instance, f, StateStale, "the daemon could not encode the snapshot")
		return
	case tooLarge:
		if f.status.State != StateStale {
			b.log.Error("remote: snapshot not sent, over the client event bound", "instance", instance, "bytes", len(data), "max", b.maxEventSize)
		}
		b.setStatus(instance, f, StateStale, "the snapshot exceeds the remote event size limit")
		return
	}

	if f.status.State == StateStale {
		b.log.Info("remote: snapshots sent again", "instance", instance)
	}
	f.hasFrankenPHP = s.HasFrankenPHP
	f.snapshot = b.newEvent(EventSnapshot, data)
	b.setStatus(instance, f, StateOK, "")
	b.fanOut(instance, func(sub *Subscription) { sub.snapshot = f.snapshot })
}

// PublishFailure reports a failed poll of instance.
func (b *Broadcaster) PublishFailure(instance string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f, ok := b.feeds[instance]; ok && !b.closed {
		b.setStatus(instance, f, StateUnreachable, err.Error())
	}
}

// setStatus emits a status event on a change of state only. Caller holds b.mu.
func (b *Broadcaster) setStatus(instance string, f *feed, state, msg string) {
	if f.status.State == state {
		return
	}
	f.status = Status{State: state, Since: b.now(), Error: msg}
	data, _ := Marshal(f.status)
	f.statusEvent = b.newEvent(EventStatus, data)
	b.fanOut(instance, func(sub *Subscription) { sub.status = f.statusEvent })
}

func (b *Broadcaster) newEvent(typ string, data []byte) *event {
	b.seq++
	return &event{seq: b.seq, typ: typ, data: data}
}

// fanOut updates the pending slot of every subscriber of instance and wakes
// it without blocking. Caller holds b.mu.
func (b *Broadcaster) fanOut(instance string, set func(*Subscription)) {
	for sub := range b.subs {
		if sub.instance != instance {
			continue
		}
		sub.mu.Lock()
		set(sub)
		sub.mu.Unlock()
		select {
		case sub.ready <- struct{}{}:
		default:
		}
	}
}

// nextID reserves an event id for an event built outside the feeds (hello).
func (b *Broadcaster) nextID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	return FormatEventID(b.epoch, b.seq)
}

func (b *Broadcaster) eventID(ev *event) string { return FormatEventID(b.epoch, ev.seq) }

// Subscription is one stream's view of an instance.
type Subscription struct {
	b        *Broadcaster
	instance string
	ready    chan struct{}

	mu       sync.Mutex
	snapshot *event
	status   *event
}

// Subscribe starts with the instance's last snapshot and, unless it is ok,
// its status, so a client joining mid-outage is not shown old data as current.
func (b *Broadcaster) Subscribe(instance string) (*Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errBroadcasterClosed
	}
	f, ok := b.feeds[instance]
	if !ok {
		return nil, fmt.Errorf("%w %q", errUnknownInstance, instance)
	}
	sub := &Subscription{b: b, instance: instance, ready: make(chan struct{}, 1), snapshot: f.snapshot}
	if f.status.State != StateOK {
		sub.status = f.statusEvent
	}
	if sub.snapshot != nil || sub.status != nil {
		sub.ready <- struct{}{}
	}
	b.subs[sub] = struct{}{}
	return sub, nil
}

func (s *Subscription) Ready() <-chan struct{} { return s.ready }

// Take returns the pending events in the order they were published.
func (s *Subscription) Take() []*event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var evs []*event
	for _, ev := range []*event{s.snapshot, s.status} {
		if ev != nil {
			evs = append(evs, ev)
		}
	}
	s.snapshot, s.status = nil, nil
	slices.SortFunc(evs, func(a, b *event) int { return cmp.Compare(a.seq, b.seq) })
	return evs
}

func (s *Subscription) Close() {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	delete(s.b.subs, s)
}

// Done is closed by Close, which ends every stream with reason shutdown.
func (b *Broadcaster) Done() <-chan struct{} { return b.done }

func (b *Broadcaster) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.done)
	}
}

// encodeLogBatches splits entries into events that each fit logBatchMaxBytes
// and logBatchMaxEntries. An entry too large on its own is dropped and counted.
func encodeLogBatches(entries []WireLogEntry, dropped int64) [][]byte {
	var (
		out   [][]byte
		batch [][]byte
		size  int
	)
	flush := func() {
		if len(batch) == 0 && dropped == 0 {
			return
		}
		out = append(out, assembleLogBatch(batch, dropped))
		batch, size, dropped = nil, 0, 0
	}
	for _, e := range entries {
		data, err := Marshal(e)
		if err != nil || logBatchOverhead(dropped)+len(data) > logBatchMaxBytes {
			dropped++
			continue
		}
		if len(batch) == logBatchMaxEntries || logBatchOverhead(dropped)+size+len(batch)+len(data) > logBatchMaxBytes {
			flush()
		}
		batch = append(batch, data)
		size += len(data)
	}
	flush()
	return out
}

// assembleLogBatch encodes a LogBatch from entries already encoded to measure them.
func assembleLogBatch(entries [][]byte, dropped int64) []byte {
	buf := []byte(`{"entries":[`)
	for i, e := range entries {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, e...)
	}
	buf = append(buf, `],"dropped":`...)
	buf = strconv.AppendInt(buf, dropped, 10)
	return append(buf, '}')
}

func logBatchOverhead(dropped int64) int {
	return len(`{"entries":[],"dropped":}`) + len(strconv.FormatInt(dropped, 10))
}
