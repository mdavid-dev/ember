package remote

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultMaxFailures   = 10
	defaultFailureWindow = time.Minute
	defaultBlockDuration = time.Minute
	defaultTrackedKeys   = 10_000
)

// RateLimiter refuses a source for blockFor after maxFailures failed
// authentications within window. A blocked source is never evicted: once
// blocked it stops failing, and an LRU would let fresh sources push it out.
// Past capacity, the least recently failing unblocked source goes; when every
// tracked source is blocked, a new one is not tracked.
type RateLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	maxFailures int
	window      time.Duration
	blockFor    time.Duration
	capacity    int
	entries     map[string]*list.Element
	counting    *list.List // unblocked, front = most recent failure
	blocked     *list.List // front = earliest expiry, as blockFor is constant
}

type rateEntry struct {
	key          string
	windowStart  time.Time
	failures     int
	blockedUntil time.Time
}

func NewRateLimiter(now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		now:         now,
		maxFailures: defaultMaxFailures,
		window:      defaultFailureWindow,
		blockFor:    defaultBlockDuration,
		capacity:    defaultTrackedKeys,
		entries:     make(map[string]*list.Element),
		counting:    list.New(),
		blocked:     list.New(),
	}
}

func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.expire(now)
	el, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	if wait := el.Value.(*rateEntry).blockedUntil.Sub(now); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Fail reports whether this failure started a block.
func (l *RateLimiter) Fail(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.expire(now)

	el, ok := l.entries[key]
	switch {
	case ok && el.Value.(*rateEntry).blockedUntil.After(now):
		return false
	case ok:
		l.counting.MoveToFront(el)
	default:
		if len(l.entries) >= l.capacity {
			victim := l.counting.Back()
			if victim == nil {
				return false
			}
			l.counting.Remove(victim)
			delete(l.entries, victim.Value.(*rateEntry).key)
		}
		el = l.counting.PushFront(&rateEntry{key: key, windowStart: now})
		l.entries[key] = el
	}

	e := el.Value.(*rateEntry)
	if now.Sub(e.windowStart) >= l.window {
		e.windowStart, e.failures = now, 0
	}
	e.failures++
	if e.failures < l.maxFailures {
		return false
	}
	l.counting.Remove(el)
	e.blockedUntil = now.Add(l.blockFor)
	l.entries[key] = l.blocked.PushBack(e)
	return true
}

// expire forgets the sources whose block is over: they start afresh.
func (l *RateLimiter) expire(now time.Time) {
	for el := l.blocked.Front(); el != nil && !el.Value.(*rateEntry).blockedUntil.After(now); el = l.blocked.Front() {
		l.blocked.Remove(el)
		delete(l.entries, el.Value.(*rateEntry).key)
	}
}

func (l *RateLimiter) tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// sourceKey keys the limiter by IPv4 address or IPv6 /64, the smallest block
// a single IPv6 host is usually given.
func sourceKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
