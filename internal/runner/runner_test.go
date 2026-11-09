package runner

import (
	"context"
	"testing"

	"github.com/KeithAGang/Ghost/internal/probe"
)

func TestLimiterHonorsCancellation(t *testing.T) {
	limiter := NewLimiter(0.1)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx); err == nil {
		t.Fatal("expected context cancellation")
	}
}

func TestControllerReducesRateOnTransportFailures(t *testing.T) {
	limiter := NewLimiter(10)
	controller := NewController(limiter, 1, 10)
	for i := 0; i < 5; i++ {
		controller.Observe(probe.Result{Stage: "tcp", ErrorKind: "tcp_timeout"})
	}
	if got := limiter.Rate(); got >= 10 {
		t.Fatalf("rate = %v, want below 10", got)
	}
}

func TestControllerPausesOn429(t *testing.T) {
	limiter := NewLimiter(10)
	controller := NewController(limiter, 1, 10)
	controller.Observe(probe.Result{Stage: "http", Status: 429})
	if got := limiter.Rate(); got >= 10 {
		t.Fatalf("rate = %v, want below 10", got)
	}
	if controller.pauseUntil.IsZero() {
		t.Fatal("expected a pause")
	}
}
