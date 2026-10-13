package exporters

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/require"
)

func TestBulkHTTPRetryPolicy(t *testing.T) {
	for _, status := range []int{400, 500, 502, 504, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				manager := NewAlertBulkManager(1, 10, 10, 3, 1000, 30000, func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
					if calls.Add(1) == 1 {
						return &httpRejection{status: status, retryAfter: "60"}
					}
					return nil
				})
				done := make(chan struct{})
				go func() { manager.processSendQueueItem(&bulkQueueItem{}); close(done) }()
				synctest.Wait()
				time.Sleep(59 * time.Second)
				synctest.Wait()
				require.EqualValues(t, 1, calls.Load())
				time.Sleep(2 * time.Second)
				<-done
				want := 1
				if status == 429 || status == 503 {
					want = 2
				}
				require.EqualValues(t, want, calls.Load())
			})
		})
	}
}

func TestBulkHTTPRetryCooldownAfterExhaustion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := NewAlertBulkManager(1, 10, 10, 1, 1000, 30000, func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
			return &httpRejection{status: 429, retryAfter: "60"}
		})
		manager.maxRetries = 0
		manager.processSendQueueItem(&bulkQueueItem{})
		var calls atomic.Int32
		manager.sendFunc = func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
			calls.Add(1)
			return nil
		}
		done := make(chan struct{})
		go func() { manager.processSendQueueItem(&bulkQueueItem{}); close(done) }()
		synctest.Wait()
		time.Sleep(59 * time.Second)
		synctest.Wait()
		require.Zero(t, calls.Load())
		time.Sleep(2 * time.Second)
		<-done
		require.EqualValues(t, 1, calls.Load())
	})
}

func TestBulkHTTPRetryCloseRespectsCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		manager := NewAlertBulkManager(1, 10, 10, 3, 1000, 30000, func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
			calls.Add(1)
			return &httpRejection{status: 429, retryAfter: "60"}
		})
		done := make(chan struct{})
		go func() { manager.processSendQueueItem(&bulkQueueItem{}); close(done) }()
		synctest.Wait()
		close(manager.stopChan)
		<-done
		require.EqualValues(t, 1, calls.Load(), "shutdown must not resend before Retry-After")
	})
}

func TestHTTPRejectionBodyDrain(t *testing.T) {
	reader := bytes.NewReader(bytes.Repeat([]byte("x"), 128<<10))
	e := retryTestExporter(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Header: make(http.Header), Body: io.NopCloser(reader)}, nil
	})
	err := e.sendHTTPBody(context.Background(), []byte("alert"))
	require.Error(t, err)
	require.Equal(t, 64<<10, reader.Len(), "rejection drainage must be bounded")
}

func TestHTTPRejectionConnectionReuse(t *testing.T) {
	addresses := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addresses <- r.RemoteAddr
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(429)
		_, _ = io.WriteString(w, "temporarily unavailable")
	}))
	defer server.Close()
	e, err := NewHTTPExporter(HTTPExporterConfig{URL: server.URL}, "", "", nil, "", armotypes.AlertSourcePlatformK8sAgent)
	require.NoError(t, err)
	defer e.Close()
	for i := 0; i < 2; i++ {
		require.Error(t, e.sendHTTPBody(context.Background(), []byte("alert")))
	}
	first, second := <-addresses, <-addresses
	require.Equal(t, first, second)
}

func TestMarshalHTTPPayloadError(t *testing.T) {
	_, err := marshalHTTPPayload(make(chan int))
	require.ErrorContains(t, err, "failed to marshal payload")
	body, err := marshalHTTPPayload(map[string]string{"alert": "same"})
	require.NoError(t, err)
	require.Contains(t, string(body), "same")
}

func TestBulkStopRespectsHTTPCooldownForQueuedBulks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		manager := NewAlertBulkManager(1, 10, 10, 3, 1000, 30000, func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
			calls.Add(1)
			return &httpRejection{status: 429, retryAfter: "60"}
		})
		for i := 0; i < 3; i++ {
			manager.sendQueue <- &bulkQueueItem{}
		}
		manager.Start()
		synctest.Wait()
		manager.Stop()
		require.EqualValues(t, 1, calls.Load(), "Stop must not bypass cooldown for queued bulks")
	})
}

func TestBulkDrainNewHTTPCooldown(t *testing.T) {
	var calls atomic.Int32
	manager := NewAlertBulkManager(1, 10, 10, 3, 1000, 30000, func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
		calls.Add(1)
		return &httpRejection{status: 429, retryAfter: "60"}
	})
	for i := 0; i < 3; i++ {
		manager.sendQueue <- &bulkQueueItem{}
	}
	manager.drainSendQueue()
	require.EqualValues(t, 1, calls.Load(), "a rejection during drain must pause subsequent bulks")
}

func TestRuleAlertRetryCooldownOutlivesExpiredAlert(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return retryTestResponse(429, "600"), nil
			}
			return retryTestResponse(200, ""), nil
		})
		e.SendRuleAlert(retryTestFailure())
		time.Sleep(301 * time.Second)
		synctest.Wait()
		e.SendRuleAlert(retryTestFailure())
		synctest.Wait()
		require.EqualValues(t, 1, calls.Load())
		time.Sleep(300 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 2, calls.Load())
	})
}

func TestRuleAlertCloseCancelsInitialSendWithQueuedFollower(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, done := make(chan struct{}), make(chan struct{})
		e := retryTestExporter(t, func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		go func() { e.SendRuleAlert(retryTestFailure()); close(done) }()
		<-started
		e.SendRuleAlert(retryTestFailure())
		before := time.Now()
		require.NoError(t, e.Close())
		<-done
		require.Equal(t, before, time.Now(), "Close must cancel the initial request rather than wait for its timeout")
	})
}

type retryTestReader func([]byte) (int, error)

func (f retryTestReader) Read(p []byte) (int, error) { return f(p) }

func TestRuleAlertRetryExpiredRejectionStillPausesEndpoint(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) {
			switch calls.Add(1) {
			case 1:
				return retryTestResponse(429, "299"), nil
			case 2:
				resp := retryTestResponse(429, "60")
				resp.Body = io.NopCloser(retryTestReader(func([]byte) (int, error) { time.Sleep(2 * time.Second); return 0, io.EOF }))
				return resp, nil
			default:
				return retryTestResponse(200, ""), nil
			}
		})
		e.SendRuleAlert(retryTestFailure())
		time.Sleep(299 * time.Second)
		synctest.Wait()
		e.SendRuleAlert(retryTestFailure())
		time.Sleep(3 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 2, calls.Load())
		time.Sleep(58 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 2, calls.Load(), "expired rejection must still set endpoint cooldown")
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 3, calls.Load())
	})
}

func TestBulkHTTPRetryLongRetryAfter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		manager := NewAlertBulkManager(1, 10, 10, 3, 1000, 30000, func(string, []armotypes.RuntimeAlert, armotypes.ProcessTree, []string) error {
			if calls.Add(1) == 1 {
				return &httpRejection{status: 503, retryAfter: "600"}
			}
			return nil
		})
		done := make(chan struct{})
		go func() { manager.processSendQueueItem(&bulkQueueItem{}); close(done) }()
		synctest.Wait()
		time.Sleep(599 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 1, calls.Load())
		time.Sleep(2 * time.Second)
		<-done
		require.EqualValues(t, 2, calls.Load())
	})
}
