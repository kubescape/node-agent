package exporters

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/http"
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
	// A malformed or excessive server hint must not silence the endpoint indefinitely.
	httpRetryMaxCooldown = 5 * time.Minute
)

type httpRejection struct {
	status     int
	retryAfter string
}

func (r *httpRejection) Error() string {
	return fmt.Sprintf("received non-2xx status code: %d", r.status)
}
func (r *httpRejection) retryable() bool {
	return r.status == http.StatusTooManyRequests || r.status == http.StatusServiceUnavailable
}

// Honor Retry-After beyond the backoff cap, up to the endpoint cooldown limit.
// Larger hints are deliberately capped so new alerts can resume delivery.
func (r *httpRejection) delay(backoff time.Duration, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(r.retryAfter, 10, 64); err == nil {
		// Bound the endpoint cooldown and avoid overflowing time.Duration.
		if seconds > uint64(httpRetryMaxCooldown/time.Second) {
			return httpRetryMaxCooldown
		}
		if delay := time.Duration(seconds) * time.Second; delay > backoff {
			return delay
		}
	} else if date, err := http.ParseTime(r.retryAfter); err == nil && date.Sub(now) > backoff {
		return min(date.Sub(now), httpRetryMaxCooldown)
	}
	return min(backoff, httpRetryMaxCooldown)
}

type ruleAlertRetry struct {
	body    []byte
	expires time.Time
	backoff time.Duration
}

// A FIFO queue shares an endpoint cooldown across pending and new rule alerts.
// The send mutex serializes cooldown checks with requests; the queue mutex never
// spans network I/O. Limits include the in-flight head. Payload bytes and alert
// identity are unchanged across attempts; ambiguous failures are not retried.
type ruleAlertRetryQueue struct {
	mu        sync.Mutex
	sendMu    sync.Mutex
	items     list.List
	initial   *ruleAlertRetry
	bytes     int
	notBefore time.Time
	nextSend  time.Time
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
	wake      chan struct{}
	wg        sync.WaitGroup
	exporter  *HTTPExporter
}

func newRuleAlertRetryQueue(e *HTTPExporter) *ruleAlertRetryQueue {
	ctx, cancel := context.WithCancel(context.Background())
	return &ruleAlertRetryQueue{ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), exporter: e}
}

// send preserves immediate healthy delivery. During cooldown, backlog, or an
// in-flight send, admission is nonblocking and the worker delivers in FIFO order.
func (q *ruleAlertRetryQueue) send(ctx context.Context, body []byte) error {
	if !q.sendMu.TryLock() {
		return q.enqueue(body, nil)
	}
	defer q.sendMu.Unlock()
	q.mu.Lock()
	deferred := q.items.Len() > 0 || time.Now().Before(q.notBefore) || time.Now().Before(q.nextSend)
	closed := q.ctx.Err() != nil
	if closed {
		q.mu.Unlock()
		return fmt.Errorf("rule alert retry queue closed")
	}
	if deferred {
		q.mu.Unlock()
		return q.enqueue(body, nil)
	}
	if err := q.admitLocked(body); err != nil {
		q.mu.Unlock()
		return err
	}
	item := &ruleAlertRetry{body: body, expires: time.Now().Add(ruleRetryRetention), backoff: time.Second}
	q.initial = item
	q.bytes += len(body)
	q.mu.Unlock()
	sendCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(q.ctx, cancel)
	err := q.exporter.sendHTTPBody(sendCtx, body)
	stop()
	cancel()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.initial = nil
	var rejection *httpRejection
	if errors.As(err, &rejection) && rejection.retryable() && q.ctx.Err() == nil {
		now := time.Now()
		q.notBefore = maxTime(q.notBefore, now.Add(rejection.delay(time.Second, now)))
		// Keep the reserved capacity and restore this older alert ahead of arrivals.
		q.items.PushFront(item)
		logger.L().Debug("HTTPExporter - queued initial rule alert for retry", helpers.Int("queuedAlerts", q.items.Len()), helpers.Int("queuedBytes", q.bytes))
		q.startWorkerLocked()
		return nil
	}
	q.bytes -= len(body)
	return err
}

func (e *HTTPExporter) enqueueRuleAlertRetry(body []byte, rejection *httpRejection) error {
	if e.ruleRetries == nil {
		return fmt.Errorf("rule alert retry queue unavailable")
	}
	return e.ruleRetries.enqueue(body, rejection)
}

func (q *ruleAlertRetryQueue) enqueue(body []byte, rejection *httpRejection) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	if rejection != nil {
		q.notBefore = maxTime(q.notBefore, now.Add(rejection.delay(time.Second, now)))
	}
	if err := q.admitLocked(body); err != nil {
		return err
	}
	q.items.PushBack(&ruleAlertRetry{body: body, expires: now.Add(ruleRetryRetention), backoff: time.Second})
	q.bytes += len(body)
	logger.L().Debug("HTTPExporter - queued rule alert for retry", helpers.Int("queuedAlerts", q.items.Len()), helpers.Int("queuedBytes", q.bytes))
	q.startWorkerLocked()
	return nil
}

// admitLocked includes the initial request's reserved slot and payload bytes.
func (q *ruleAlertRetryQueue) admitLocked(body []byte) error {
	initial := 0
	if q.initial != nil {
		initial = 1
	}
	reason := ""
	switch {
	case q.ctx.Err() != nil:
		reason = "closed"
	case q.items.Len()+initial >= ruleRetryQueueSize:
		reason = "count_limit"
	case len(body) > ruleRetryQueueBytes-q.bytes:
		reason = "byte_limit"
	}
	if reason != "" {
		logger.L().Warning("HTTPExporter - dropping rule alert", helpers.String("reason", reason), helpers.Int("queuedAlerts", q.items.Len()+initial), helpers.Int("queuedBytes", q.bytes))
		return fmt.Errorf("rule alert retry queue admission failed: %s", reason)
	}
	return nil
}

func (q *ruleAlertRetryQueue) startWorkerLocked() {
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

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

func (q *ruleAlertRetryQueue) close() {
	q.mu.Lock()
	q.cancel()
	q.mu.Unlock()
	q.wg.Wait()
	// Join any initial request before clearing its reserved bytes.
	q.sendMu.Lock()
	defer q.sendMu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.items.Len() > 0 {
		logger.L().Warning("HTTPExporter - dropping pending rule alerts", helpers.String("reason", "shutdown"), helpers.Int("alertCount", q.items.Len()), helpers.Int("queuedBytes", q.bytes))
	}
	q.items.Init()
	q.bytes = 0
}

func (q *ruleAlertRetryQueue) removeHead(err error) {
	head := q.items.Front()
	q.bytes -= len(head.Value.(*ruleAlertRetry).body)
	q.items.Remove(head)
	head.Value = nil
	if err != nil {
		logger.L().Warning("HTTPExporter - dropping rule alert after retry", helpers.Error(err))
	} else {
		logger.L().Debug("HTTPExporter - delivered queued rule alert")
	}
}

func (q *ruleAlertRetryQueue) run() {
	defer q.wg.Done()
	for {
		q.mu.Lock()
		if q.ctx.Err() != nil || q.items.Len() == 0 {
			q.running = false
			q.mu.Unlock()
			return
		}
		item := q.items.Front().Value.(*ruleAlertRetry)
		now := time.Now()
		if !now.Before(item.expires) {
			q.removeHead(fmt.Errorf("rule alert retry retention expired"))
			q.mu.Unlock()
			continue
		}
		due := maxTime(q.notBefore, q.nextSend)
		if item.expires.Before(due) {
			due = item.expires
		}
		delay := due.Sub(now)
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
		q.sendMu.Lock()
		q.mu.Lock()
		// A rejected initial request may have become the new head while we
		// waited for sendMu. Always select the current head after taking it.
		if q.items.Len() == 0 {
			q.mu.Unlock()
			q.sendMu.Unlock()
			continue
		}
		item = q.items.Front().Value.(*ruleAlertRetry)
		now = time.Now()
		if q.ctx.Err() != nil || now.Before(q.notBefore) || now.Before(q.nextSend) || !now.Before(item.expires) {
			q.mu.Unlock()
			q.sendMu.Unlock()
			continue
		}
		q.mu.Unlock()
		ctx, cancel := context.WithDeadline(q.ctx, item.expires)
		err := q.exporter.sendHTTPBody(ctx, item.body)
		cancel()
		q.mu.Lock()
		now = time.Now()
		rate := q.exporter.config.MaxAlertsPerMinute
		if rate <= 0 {
			rate = defaultMaxAlertsPerMin
		}
		q.nextSend = now.Add(max(time.Millisecond, time.Minute/time.Duration(rate)))
		var rejection *httpRejection
		if errors.As(err, &rejection) && rejection.retryable() {
			item.backoff = min(item.backoff*2, ruleRetryMaxDelay)
			q.notBefore = maxTime(q.notBefore, now.Add(rejection.delay(item.backoff, now)))
			if !now.Before(item.expires) {
				q.removeHead(fmt.Errorf("rule alert retry retention expired: %w", err))
			}
			logger.L().Debug("HTTPExporter - rule alert retry deferred", helpers.Error(err), helpers.String("retryAt", q.notBefore.Format(time.RFC3339)))
		} else {
			q.removeHead(err)
		}
		q.mu.Unlock()
		q.sendMu.Unlock()
	}
}
