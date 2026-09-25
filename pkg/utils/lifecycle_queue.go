package utils

import "sync"

// LifecycleQueue runs callbacks in submission order for each key, without
// blocking unrelated containers. The zero value is ready for use. Idle keys
// are removed, so the queue does not retain every container ever observed.
type LifecycleQueue struct {
	mu    sync.Mutex
	tails map[string]chan struct{}
}

func (q *LifecycleQueue) Submit(key string, callback func()) {
	q.mu.Lock()
	if q.tails == nil {
		q.tails = make(map[string]chan struct{})
	}
	previous := q.tails[key]
	done := make(chan struct{})
	q.tails[key] = done
	q.mu.Unlock()
	go func() {
		defer func() {
			q.mu.Lock()
			if q.tails[key] == done {
				delete(q.tails, key)
			}
			close(done)
			q.mu.Unlock()
		}()
		if previous != nil {
			<-previous
		}
		callback()
	}()
}
