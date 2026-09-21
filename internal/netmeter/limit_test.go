package netmeter

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

// TestTheCapActuallyPacesTheRead.
//
// The cap exists because a saturated downlink ruined a video call on the same
// connection, and the mechanism is indirect enough to be worth pinning: nothing
// here limits the network, it limits how fast the bytes are CONSUMED, and TCP's
// receive window does the rest. So what this asserts is the only thing this
// package controls — that reading 3 MB through a 1 MB/s reader takes about
// three seconds.
//
// Time is injected rather than slept, so the test is exact and instant. The
// real time.After in take() is the one thing not exercised; it is three lines
// and a select.
func TestTheCapActuallyPacesTheRead(t *testing.T) {
	t.Cleanup(func() { SetLimit(0) })

	const perSec = 1 << 20 // 1 MB/s
	SetLimit(perSec)

	// A clock that advances by exactly what each wait asks for, which is what
	// a real sleep would have done.
	var elapsed time.Duration
	base := time.Unix(0, 0)
	b := limiter.Load()
	b.now = func() time.Time { return base.Add(elapsed) }
	b.last = b.now()
	slept := time.Duration(0)
	b.sleep = func(_ context.Context, d time.Duration) error {
		elapsed += d
		slept += d
		return nil
	}

	data := bytes.Repeat([]byte("x"), 3<<20)
	n, err := io.Copy(io.Discard, Reader(context.Background(), "t", bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Fatalf("copied %d bytes, want %d", n, len(data))
	}

	// 3 MB at 1 MB/s is three seconds, less the burst that was waiting in the
	// bucket when the read started.
	want := 3*time.Second - time.Duration(float64(b.burst)/perSec*float64(time.Second))
	if slept < want-100*time.Millisecond || slept > 3*time.Second+100*time.Millisecond {
		t.Errorf("paced 3 MB at 1 MB/s into %v, want about %v", slept, want)
	}
}

// Uncapped must be genuinely uncapped: the default, and what every deployment
// on a link nobody else shares should run.
func TestNoLimitDoesNotPace(t *testing.T) {
	SetLimit(0)
	if l := Limit(); l != 0 {
		t.Fatalf("Limit() = %v after SetLimit(0), want 0", l)
	}
	data := bytes.Repeat([]byte("x"), 8<<20)
	start := time.Now()
	if _, err := io.Copy(io.Discard, Reader(context.Background(), "t", bytes.NewReader(data))); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("8 MB took %v with no limit set; something is pacing it", d)
	}
}

// A cancelled context must not leave a download spinning: the shaper is in the
// read path of a 284 MB proof, and a shutdown mid-proof has to return.
func TestACancelledContextStopsWaiting(t *testing.T) {
	t.Cleanup(func() { SetLimit(0) })
	SetLimit(1 << 10) // 1 KB/s: anything real will have to wait

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	data := bytes.Repeat([]byte("x"), 1<<20)
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, Reader(ctx, "t", bytes.NewReader(data)))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a cancelled read returned nil; the wait swallowed the cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled read did not return; the shaper ignores its context")
	}
}
