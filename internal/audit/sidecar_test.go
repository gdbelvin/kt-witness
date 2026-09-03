package audit

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestPoolBoundsConcurrency is the property that keeps the host alive: never
// more simultaneous verifications than workers.
//
// Exceeding it is not a slowdown, it is an OOM kill of the whole witness — and
// equivocation detection dies with it. So the bound is asserted rather than
// assumed.
func TestPoolBoundsConcurrency(t *testing.T) {
	const workers, callers = 3, 12
	p := NewPool("/nonexistent-binary", workers)

	var mu sync.Mutex
	var inFlight, peak int
	var wg sync.WaitGroup

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Borrow a worker directly: Verify would fail on the missing
			// binary, and what is under test is the checkout discipline.
			s := <-p.free
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			p.free <- s
		}()
	}
	wg.Wait()

	if peak > workers {
		t.Fatalf("peak concurrency %d exceeded pool size %d", peak, workers)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency %d: the pool is not actually running work in parallel", peak)
	}
	if len(p.free) != workers {
		t.Fatalf("%d workers returned to the pool, want %d: a leak shrinks capacity silently", len(p.free), workers)
	}
}

// TestPoolSizeFloor guards against a configuration that would deadlock.
func TestPoolSizeFloor(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got := NewPool("/x", n).Size(); got != 1 {
			t.Fatalf("NewPool size %d gave %d, want 1: a zero pool blocks forever", n, got)
		}
	}
}

// TestPoolReturnsWorkerAfterFailure checks a crashed worker does not shrink the
// pool permanently.
func TestPoolReturnsWorkerAfterFailure(t *testing.T) {
	p := NewPool("/nonexistent-binary", 2)
	for i := 0; i < 5; i++ {
		// Every call fails to start the binary; the worker must still come back.
		_, err := p.Verify(context.Background(), "d", 1, "a", "b", time.Second)
		if err == nil {
			t.Fatal("expected a start failure for a missing binary")
		}
	}
	if len(p.free) != 2 {
		t.Fatalf("pool has %d workers after failures, want 2", len(p.free))
	}
}
