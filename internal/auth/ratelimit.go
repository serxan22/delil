package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a per-key token-bucket rate limiter kept in memory. Limits are
// per instance; behind a load balancer the effective limit is multiplied by
// the number of instances (documented in docs/deployment.md).
type Limiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	buckets map[string]*bucket
	ttl     time.Duration
	lastGC  time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewLimiter allows rps requests per second with the given burst per key.
func NewLimiter(rps float64, burst int) *Limiter {
	return &Limiter{limit: rate.Limit(rps), burst: burst, buckets: map[string]*bucket{}, ttl: 10 * time.Minute}
}

// NewWindowLimiter allows n requests per window with burst n.
func NewWindowLimiter(n int, window time.Duration) *Limiter {
	return NewLimiter(float64(n)/window.Seconds(), n)
}

// Allow reports whether a request for key may proceed now. When it may not,
// retryAfter is the time until a token is available.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	now := time.Now()
	l.mu.Lock()
	b, exists := l.buckets[key]
	if !exists {
		b = &bucket{lim: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	if now.Sub(l.lastGC) > l.ttl {
		for k, v := range l.buckets {
			if now.Sub(v.seen) > l.ttl {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	l.mu.Unlock()

	r := b.lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Second
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}
