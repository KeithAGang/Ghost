package runner

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces new probes. It is deliberately connection-oriented: on a
// mobile network the new TCP/TLS handshake is the expensive and visible part.
type Limiter struct {
	mu   sync.Mutex
	rate float64
	next time.Time
}

func NewLimiter(rps float64) *Limiter {
	if rps <= 0 {
		rps = 1
	}
	return &Limiter{rate: rps}
}

// Wait reserves the next probe slot and blocks until it is due.
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	interval := time.Duration(float64(time.Second) / l.rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	l.next = l.next.Add(interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	return sleepContext(ctx, wait)
}

func (l *Limiter) SetRate(rps float64) {
	if rps < 0.1 {
		rps = 0.1
	}
	l.mu.Lock()
	l.rate = rps
	l.mu.Unlock()
}

func (l *Limiter) Rate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
