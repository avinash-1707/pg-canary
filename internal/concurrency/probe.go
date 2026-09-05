// Package concurrency runs explicitly opted-in concurrent probes.
package concurrency

import (
	"context"
	"fmt"
	"sync"
)

type Probe func(context.Context, int) error

// Run starts workers at one barrier and returns every worker error.
func Run(ctx context.Context, workers int, probe Probe) []error {
	if workers < 1 {
		return []error{fmt.Errorf("workers must be positive")}
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	var lock sync.Mutex
	var errs []error
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(id int) {
			defer group.Done()
			<-start
			if err := probe(ctx, id); err != nil {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
		}(worker)
	}
	close(start)
	group.Wait()
	return errs
}
