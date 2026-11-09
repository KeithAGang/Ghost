// Package runner schedules probed candidates with bounded concurrency and an
// adaptive connection rate.
package runner

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/KeithAGang/Ghost/internal/probe"
	"github.com/KeithAGang/Ghost/internal/report"
	"github.com/KeithAGang/Ghost/internal/sampler"
)

type Config struct {
	Target        probe.Target
	Concurrency   int
	Rate          float64
	MinRate       float64
	MaxRate       float64
	CooldownEvery int
	Cooldown      time.Duration
	Seed          int64
}

type Runner struct {
	cfg Config
	rng *rand.Rand
}

func New(cfg Config) *Runner {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 1
	}
	if cfg.MinRate <= 0 {
		cfg.MinRate = 0.1
	}
	if cfg.MaxRate <= 0 {
		cfg.MaxRate = cfg.Rate
	}
	if cfg.MaxRate < cfg.MinRate {
		cfg.MaxRate = cfg.MinRate
	}
	if cfg.Cooldown < 0 {
		cfg.Cooldown = 0
	}
	if cfg.CooldownEvery < 0 {
		cfg.CooldownEvery = 0
	}
	if cfg.Target.Timeout <= 0 {
		cfg.Target.Timeout = 8 * time.Second
	}
	if cfg.Target.Port == 0 {
		cfg.Target.Port = 443
	}
	if cfg.Target.Path == "" {
		cfg.Target.Path = "/"
	}
	return &Runner{
		cfg: cfg,
		rng: rand.New(rand.NewSource(cfg.Seed)),
	}
}

// Run probes all candidates and calls emit once per result. emit is called from
// a single goroutine, so it does not need its own locking.
func (r *Runner) Run(ctx context.Context, candidates []sampler.Candidate, emit func(probe.Result) error) (report.Summary, error) {
	var summary report.Summary
	if len(candidates) == 0 {
		summary.Finalize()
		return summary, errors.New("no candidates to probe")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	limiter := NewLimiter(r.cfg.Rate)
	controller := NewController(limiter, r.cfg.MinRate, r.cfg.MaxRate)

	jobs := make(chan sampler.Candidate)
	results := make(chan probe.Result)
	var workers sync.WaitGroup

	for i := 0; i < r.cfg.Concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				if err := controller.Before(runCtx); err != nil {
					return
				}
				probeCtx, probeCancel := context.WithTimeout(runCtx, r.cfg.Target.Timeout)
				result := probe.Probe(probeCtx, candidate.Addr, candidate.Prefix, r.cfg.Target)
				probeCancel()
				controller.Observe(result)

				select {
				case results <- result:
				case <-runCtx.Done():
					return
				}
			}
		}()
	}

	var (
		firstErr error
		errMu    sync.Mutex
	)
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for result := range results {
			summary.Add(result)
			if err := emit(result); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				errMu.Unlock()
			}
		}
	}()

	go func() {
		defer close(jobs)
		for i, candidate := range candidates {
			if r.cfg.CooldownEvery > 0 && i > 0 && i%r.cfg.CooldownEvery == 0 {
				if err := sleepContext(runCtx, r.cooldown()); err != nil {
					return
				}
			}
			select {
			case jobs <- candidate:
			case <-runCtx.Done():
				return
			}
		}
	}()

	workers.Wait()
	close(results)
	<-collectorDone
	summary.Finalize()

	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	if err != nil {
		return summary, err
	}
	if ctx.Err() != nil {
		return summary, ctx.Err()
	}
	return summary, nil
}

func (r *Runner) cooldown() time.Duration {
	if r.cfg.Cooldown <= 0 {
		return 0
	}
	jitter := time.Duration(r.rng.Int63n(int64(r.cfg.Cooldown/2 + 1)))
	return r.cfg.Cooldown + jitter
}
