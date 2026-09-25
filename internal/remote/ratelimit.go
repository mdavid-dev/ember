package remote

import (
	"container/list"
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
// authentications within window. Past capacity, the least recently failing
// source is forgotten.
type RateLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	maxFailures int
	window      time.Duration
	blockFor    time.Duration
	capacity    int
	entries     map[string]*list.Element
	lru         *list.List // front = most recent failure
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
		lru:         list.New(),
	}
}

func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	if wait := el.Value.(*rateEntry).blockedUntil.Sub(l.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

func (l *RateLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	var e *rateEntry
	if el, ok := l.entries[key]; ok {
		l.lru.MoveToFront(el)
		e = el.Value.(*rateEntry)
	} else {
		if l.lru.Len() >= l.capacity {
			oldest := l.lru.Back()
			l.lru.Remove(oldest)
			delete(l.entries, oldest.Value.(*rateEntry).key)
		}
		e = &rateEntry{key: key, windowStart: now}
		l.entries[key] = l.lru.PushFront(e)
	}

	if now.Sub(e.windowStart) >= l.window {
		e.windowStart, e.failures = now, 0
	}
	e.failures++
	if e.failures >= l.maxFailures {
		// Count afresh after the block, so one more failure cannot re-block.
		e.blockedUntil = now.Add(l.blockFor)
		e.windowStart, e.failures = e.blockedUntil, 0
	}
}

func (l *RateLimiter) tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}
