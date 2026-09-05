package concurrency

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestRunStartsEveryWorker(t *testing.T) {
	var ran int32
	errs := Run(context.Background(), 4, func(context.Context, int) error { atomic.AddInt32(&ran, 1); return nil })
	if len(errs) != 0 || ran != 4 {
		t.Fatalf("errors=%v ran=%d", errs, ran)
	}
}
