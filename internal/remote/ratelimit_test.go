package remote

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func failN(l *RateLimiter, key string, n int) {
	for range n {
		l.Fail(key)
	}
}

func TestRateLimiter_BlocksAfterTenFailures(t *testing.T) {
	clock := &fakeClock{t: fixtureTime}
	l := NewRateLimiter(clock.Now)

	failN(l, "a", defaultMaxFailures-1)
	ok, _ := l.Allow("a")
	require.True(t, ok, "nine failures are tolerated")

	l.Fail("a")
	ok, wait := l.Allow("a")
	require.False(t, ok)
	assert.Equal(t, time.Minute, wait)

	ok, _ = l.Allow("b")
	assert.True(t, ok, "sources are independent")
}

func TestRateLimiter_BlockEndsAndCountRestarts(t *testing.T) {
	clock := &fakeClock{t: fixtureTime}
	l := NewRateLimiter(clock.Now)
	failN(l, "a", defaultMaxFailures)

	clock.Advance(time.Minute - time.Nanosecond)
	ok, wait := l.Allow("a")
	require.False(t, ok)
	assert.Equal(t, time.Nanosecond, wait)

	clock.Advance(time.Nanosecond)
	ok, _ = l.Allow("a")
	require.True(t, ok, "back to normal once the block is over")

	failN(l, "a", defaultMaxFailures-1)
	ok, _ = l.Allow("a")
	assert.True(t, ok, "a source that waited the block out starts from zero")
	l.Fail("a")
	ok, _ = l.Allow("a")
	assert.False(t, ok)
}

func TestRateLimiter_WindowExpires(t *testing.T) {
	clock := &fakeClock{t: fixtureTime}
	l := NewRateLimiter(clock.Now)
	failN(l, "a", defaultMaxFailures-1)
	clock.Advance(time.Minute)
	failN(l, "a", defaultMaxFailures-1)
	ok, _ := l.Allow("a")
	assert.True(t, ok, "failures spread over two windows never add up to a block")
}

func TestRateLimiter_MemoryIsBounded(t *testing.T) {
	clock := &fakeClock{t: fixtureTime}
	l := NewRateLimiter(clock.Now)
	failN(l, "first", defaultMaxFailures)
	ok, _ := l.Allow("first")
	require.False(t, ok)

	for i := range defaultTrackedKeys {
		l.Fail(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	assert.Equal(t, defaultTrackedKeys, l.tracked())

	ok, _ = l.Allow("first")
	assert.True(t, ok, "the least recently failing source is the one forgotten")

	l.Fail("10.0.0.0")
	l.Fail("new")
	assert.Equal(t, defaultTrackedKeys, l.tracked())
	_, kept := l.entries["10.0.0.0"]
	assert.True(t, kept, "a fresh failure moves a source to the front of the LRU")
	_, evicted := l.entries["10.0.0.1"]
	assert.False(t, evicted)
}

func TestRateLimiter_AllowDoesNotTrack(t *testing.T) {
	l := NewRateLimiter(nil)
	for i := range 100 {
		l.Allow(fmt.Sprint(i))
	}
	assert.Zero(t, l.tracked(), "only failures take memory")
}

func TestRateLimiter_Concurrent(t *testing.T) {
	l := NewRateLimiter(nil)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 500 {
				key := fmt.Sprintf("%d-%d", g, i%20)
				l.Fail(key)
				l.Allow(key)
			}
		})
	}
	wg.Wait()
	assert.Equal(t, 160, l.tracked())
}
