package exporters

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	ruleRetryQueueSize  = 1000
	ruleRetryQueueBytes = 16 << 20
	ruleRetryRetention  = 5 * time.Minute
	ruleRetryMaxDelay   = 30 * time.Second
)

type httpRejection struct {
	status     int
	retryAfter string
}

func (r *httpRejection) Error() string {
	return fmt.Sprintf("received non-2xx status code: %d", r.status)
}
func (r *httpRejection) retryable() bool {
	return r.status == http.StatusTooManyRequests || r.status >= 500 && r.status <= 599
}

// Retry-After is a lower bound, including when it exceeds our backoff cap.
func (r *httpRejection) delay(backoff time.Duration, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(r.retryAfter, 10, 64); err == nil {
		// Avoid overflowing time.Duration on an untrusted header.
		if seconds > uint64(ruleRetryRetention/time.Second) {
			return ruleRetryRetention + time.Second
		}
		if delay := time.Duration(seconds) * time.Second; delay > backoff {
			return delay
		}
	} else if date, err := http.ParseTime(r.retryAfter); err == nil && date.Sub(now) > backoff {
		return date.Sub(now)
	}
	return backoff
}

type ruleAlertRetry struct {
	body        []byte
	nextAttempt time.Time
	expires     time.Time
	backoff     time.Duration
}

// The scheduler keeps one immutable serialized payload per alert. A single
// worker selects the next due alert so one Retry-After cannot block other alerts.
// Limits include the in-flight retry. Pending alerts are discarded on shutdown.
// Only explicit HTTP rejections are retried: transport errors have ambiguous
// delivery status. Alert uniqueID and timestamp are preserved on every attempt.
type ruleAlertRetryQueue struct {
	mu       sync.Mutex
	items    []*ruleAlertRetry
	bytes    int
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	wg       sync.WaitGroup
	exporter *HTTPExporter
}

func newRuleAlertRetryQueue(e *HTTPExporter) *ruleAlertRetryQueue {
	ctx, cancel := context.WithCancel(context.Background())
	return &ruleAlertRetryQueue{ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), exporter: e}
}

func (e *HTTPExporter) enqueueRuleAlertRetry(body []byte, rejection *httpRejection) {
	if e.ruleRetries == nil {
		return
	}
	q := e.ruleRetries
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ctx.Err() != nil || len(q.items) >= ruleRetryQueueSize || len(body) > ruleRetryQueueBytes-q.bytes {
		logger.L().Warning("HTTPExporter - dropping rule alert, retry queue full or closed")
		return
	}
	now := time.Now()
	q.items = append(q.items, &ruleAlertRetry{body: body, nextAttempt: now.Add(rejection.delay(time.Second, now)), expires: now.Add(ruleRetryRetention), backoff: time.Second})
	q.bytes += len(body)
	if !q.running {
		q.running = true
		q.wg.Add(1)
		go q.run()
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *ruleAlertRetryQueue) close() {
	q.mu.Lock()
	q.cancel()
	q.mu.Unlock()
	q.wg.Wait()
	q.mu.Lock()
	q.items = nil
	q.bytes = 0
	q.mu.Unlock()
}

func (q *ruleAlertRetryQueue) run() {
	defer q.wg.Done()
	for {
		q.mu.Lock()
		if q.ctx.Err() != nil || len(q.items) == 0 {
			q.running = false
			q.mu.Unlock()
			return
		}
		index := 0
		due := func(item *ruleAlertRetry) time.Time {
			if item.expires.Before(item.nextAttempt) {
				return item.expires
			}
			return item.nextAttempt
		}
		for i := 1; i < len(q.items); i++ {
			if due(q.items[i]).Before(due(q.items[index])) {
				index = i
			}
		}
		item := q.items[index]
		delay := time.Until(due(item))
		q.mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-q.wake:
			case <-q.ctx.Done():
			}
			timer.Stop()
			continue
		}
		var err error
		if time.Now().Before(item.expires) {
			ctx, cancel := context.WithDeadline(q.ctx, item.expires)
			err = q.exporter.sendHTTPBody(ctx, item.body)
			cancel()
		} else {
			err = fmt.Errorf("rule alert retry retention expired")
		}
		q.mu.Lock()
		var rejection *httpRejection
		if errors.As(err, &rejection) && rejection.retryable() && time.Now().Before(item.expires) {
			item.backoff = min(item.backoff*2, ruleRetryMaxDelay)
			item.nextAttempt = time.Now().Add(rejection.delay(item.backoff, time.Now()))
		} else {
			q.bytes -= len(item.body)
			q.items = slices.Delete(q.items, index, index+1)
			if err != nil {
				logger.L().Warning("HTTPExporter - dropping rule alert after retry", helpers.Error(err))
			}
		}
		q.mu.Unlock()
	}
}
