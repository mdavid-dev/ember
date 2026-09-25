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

func TestRateLimiter_BlockedSourceIsNeverEvicted(t *testing.T) {
	clock := &fakeClock{t: fixtureTime}
	l := NewRateLimiter(clock.Now)
	failN(l, "attacker", defaultMaxFailures)

	for i := range defaultTrackedKeys {
		l.Fail(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	assert.Equal(t, defaultTrackedKeys, l.tracked())
	ok, _ := l.Allow("attacker")
	assert.False(t, ok, "fresh failing sources must not push a blocked one out")
}

func TestRateLimiter_EvictsLeastRecentUnblocked(t *testing.T) {
	l := NewRateLimiter(nil)
	for i := range defaultTrackedKeys {
		l.Fail(fmt.Sprint(i))
	}
	l.Fail("0")
	l.Fail("new")
	assert.Equal(t, defaultTrackedKeys, l.tracked())
	_, kept := l.entries["0"]
	assert.True(t, kept, "a fresh failure moves a source to the front")
	_, evicted := l.entries["1"]
	assert.False(t, evicted)
}

func TestRateLimiter_AllBlockedLeavesNewSourcesUntracked(t *testing.T) {
	clock := &fakeClock{t: fixtureTime}
	l := NewRateLimiter(clock.Now)
	l.capacity = 3
	for _, k := range []string{"a", "b", "c"} {
		failN(l, k, defaultMaxFailures)
	}
	failN(l, "d", 2*defaultMaxFailures)
	assert.Equal(t, 3, l.tracked())
	ok, _ := l.Allow("d")
	assert.True(t, ok, "not tracked, so not blocked: the table stays bounded")

	clock.Advance(time.Minute)
	failN(l, "d", defaultMaxFailures)
	ok, _ = l.Allow("d")
	assert.False(t, ok, "expired blocks free their slots")
	assert.Equal(t, 1, l.tracked())
}

func TestRateLimiter_FailReportsTheBlockTransition(t *testing.T) {
	l := NewRateLimiter(nil)
	for i := 1; i < defaultMaxFailures; i++ {
		assert.False(t, l.Fail("a"))
	}
	assert.True(t, l.Fail("a"))
	assert.False(t, l.Fail("a"), "already blocked")
}

func TestSourceKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:5000":          "192.0.2.1",
		"[::ffff:192.0.2.1]:1":    "192.0.2.1",
		"[2001:db8::1]:443":       "2001:db8::/64",
		"[2001:db8::ffff:1]:443":  "2001:db8::/64",
		"[2001:DB8:0:0:1::1]:443": "2001:db8::/64",
		"[2001:db8:0:1::1]:443":   "2001:db8:0:1::/64",
		"[fe80::1%eth0]:1":        "fe80::/64",
		"192.0.2.1":               "192.0.2.1",
		"not-an-address":          "not-an-address",
		"proxy.internal:8080":     "proxy.internal",
		"[2001:db8::1%25zone]:80": "2001:db8::/64",
	} {
		assert.Equal(t, want, sourceKey(in), in)
	}
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
