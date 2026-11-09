package runner

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/KeithAGang/Ghost/internal/probe"
)

// Controller adapts the connection rate to observed behavior.
//
// It never increases above the configured maximum. Sustained transport
// failures halve the rate and pause briefly; a 429 or a challenge response
// pauses for a minute.
type Controller struct {
	mu         sync.Mutex
	lim        *Limiter
	min, max   float64
	failStreak int
	okStreak   int
	pauseUntil time.Time
}

func NewController(lim *Limiter, minRate, maxRate float64) *Controller {
	if minRate <= 0 {
		minRate = 0.1
	}
	if maxRate < minRate {
		maxRate = minRate
	}
	return &Controller{lim: lim, min: minRate, max: maxRate}
}

func (c *Controller) Before(ctx context.Context) error {
	for {
		c.mu.Lock()
		pause := time.Until(c.pauseUntil)
		c.mu.Unlock()
		if pause <= 0 {
			break
		}
		if err := sleepContext(ctx, pause); err != nil {
			return err
		}
	}
	return c.lim.Wait(ctx)
}

func (c *Controller) Observe(result probe.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if result.Status == 429 || strings.EqualFold(result.CFMitigated, "challenge") {
		c.pauseUntil = time.Now().Add(60 * time.Second)
		c.lim.SetRate(clamp(c.lim.Rate()/2, c.min, c.max))
		c.failStreak = 0
		c.okStreak = 0
		return
	}

	// Any HTTP response proves the path is not blackholed, even if the status
	// is 403 or 500.
	if result.Stage == "http" {
		c.okStreak++
		c.failStreak = 0
		if c.okStreak >= 10 {
			c.lim.SetRate(clamp(c.lim.Rate()*1.25, c.min, c.max))
			c.okStreak = 0
		}
		return
	}

	c.failStreak++
	c.okStreak = 0
	if c.failStreak >= 5 {
		c.lim.SetRate(clamp(c.lim.Rate()/2, c.min, c.max))
		c.pauseUntil = time.Now().Add(15 * time.Second)
		c.failStreak = 0
	}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
