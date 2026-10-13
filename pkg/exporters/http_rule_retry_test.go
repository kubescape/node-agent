package exporters

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/stretchr/testify/require"
)

type retryTestTransport func(*http.Request) (*http.Response, error)

func (f retryTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func retryTestExporter(t *testing.T, transport retryTestTransport) *HTTPExporter {
	t.Helper()
	e, err := NewHTTPExporter(HTTPExporterConfig{URL: "http://synchronizer", MaxAlertsPerMinute: 2000}, "cluster", "node", nil, "uid", armotypes.AlertSourcePlatformK8sAgent)
	require.NoError(t, err)
	e.httpClient.Transport = transport
	t.Cleanup(func() { require.NoError(t, e.Close()) })
	return e
}

func retryTestFailure() *types.GenericRuleFailure {
	return &types.GenericRuleFailure{BaseRuntimeAlert: armotypes.BaseRuntimeAlert{AlertName: "Unexpected process launched", UniqueID: "stable-alert-id", Timestamp: time.Now()}}
}

func retryTestResponse(status int, after string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{after}}, Body: io.NopCloser(strings.NewReader(""))}
}

func TestRuleAlertRetryReconnect(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				var mu sync.Mutex
				var bodies []string
				successes := 0
				e := retryTestExporter(t, func(r *http.Request) (*http.Response, error) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return nil, err
					}
					mu.Lock()
					defer mu.Unlock()
					bodies = append(bodies, string(body))
					if time.Since(start) <= 60*time.Second {
						return retryTestResponse(status, "60"), nil
					}
					successes++
					return retryTestResponse(200, ""), nil
				})
				failure := retryTestFailure()
				e.SendRuleAlert(failure)
				// Changing the original failure cannot alter the queued snapshot.
				failure.BaseRuntimeAlert.UniqueID = "mutated"
				synctest.Wait()
				time.Sleep(59 * time.Second)
				synctest.Wait()
				mu.Lock()
				require.Len(t, bodies, 1, "must honor Retry-After")
				mu.Unlock()
				time.Sleep(62 * time.Second)
				synctest.Wait()
				mu.Lock()
				require.Len(t, bodies, 3)
				require.Equal(t, bodies[0], bodies[1])
				require.Equal(t, bodies[0], bodies[2])
				require.Contains(t, bodies[2], "stable-alert-id")
				require.Equal(t, 1, successes)
				mu.Unlock()
				time.Sleep(5 * time.Minute)
				synctest.Wait()
				mu.Lock()
				require.Len(t, bodies, 3, "must stop retrying after success")
				mu.Unlock()
			})
		})
	}
}

func TestRuleAlertRetryBackoffAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts []time.Time
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) {
			attempts = append(attempts, time.Now())
			return retryTestResponse(503, "invalid"), nil
		})
		e.SendRuleAlert(retryTestFailure())
		synctest.Wait()
		time.Sleep(ruleRetryRetention + time.Second)
		synctest.Wait()
		require.Greater(t, len(attempts), 7)
		require.Equal(t, time.Second, attempts[1].Sub(attempts[0]))
		require.Equal(t, 2*time.Second, attempts[2].Sub(attempts[1]))
		require.Equal(t, ruleRetryMaxDelay, attempts[6].Sub(attempts[5]))
		require.Less(t, attempts[len(attempts)-1].Sub(attempts[0]), ruleRetryRetention)
		require.Zero(t, e.ruleRetries.items.Len())
		require.Zero(t, e.ruleRetries.bytes)
	})
}

func TestRuleAlertRetryPermanentAndAmbiguousFailures(t *testing.T) {
	for _, status := range []int{200, 400, 401, 404, 408, 500, 502, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return retryTestResponse(status, ""), nil })
				e.SendRuleAlert(retryTestFailure())
				time.Sleep(6 * time.Minute)
				synctest.Wait()
				require.EqualValues(t, 1, calls.Load())
			})
		})
	}
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, errors.New("connection reset") })
		e.SendRuleAlert(retryTestFailure())
		time.Sleep(6 * time.Minute)
		synctest.Wait()
		require.EqualValues(t, 1, calls.Load())
	})
}

func TestRuleAlertRetryQueueBoundsAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return retryTestResponse(429, "60"), nil })
		for i := 0; i < ruleRetryQueueSize+1; i++ {
			e.SendRuleAlert(retryTestFailure())
		}
		synctest.Wait()
		require.Equal(t, ruleRetryQueueSize, e.ruleRetries.items.Len())
		require.NoError(t, e.Close())
		require.NoError(t, e.Close())
		time.Sleep(61 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 1, calls.Load(), "new alerts must queue without hitting cooling endpoint")
		require.Zero(t, e.ruleRetries.items.Len())
		e.enqueueRuleAlertRetry([]byte("closed"), &httpRejection{status: 429})
		require.Zero(t, e.ruleRetries.items.Len())
	})
	synctest.Test(t, func(t *testing.T) {
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { return retryTestResponse(429, "60"), nil })
		e.enqueueRuleAlertRetry(make([]byte, ruleRetryQueueBytes), &httpRejection{status: 429})
		e.enqueueRuleAlertRetry([]byte("overflow"), &httpRejection{status: 429})
		synctest.Wait()
		require.Equal(t, 1, e.ruleRetries.items.Len())
		require.Equal(t, ruleRetryQueueBytes, e.ruleRetries.bytes)
	})
}

func TestRuleAlertRetrySharedSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return retryTestResponse(200, ""), nil })
		e.enqueueRuleAlertRetry([]byte("slow"), &httpRejection{status: 429, retryAfter: "60"})
		e.enqueueRuleAlertRetry([]byte("fast"), &httpRejection{status: 503})
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 0, calls.Load(), "shared endpoint cooldown gates every alert")
		time.Sleep(60 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 2, calls.Load())
	})
}

func TestHTTPRejectionRetryAfter(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tt := range []struct {
		header string
		want   time.Duration
	}{
		{"60", time.Minute}, {now.Add(time.Minute).Format(http.TimeFormat), time.Minute},
		{"", time.Second}, {"bogus", time.Second}, {"-1", time.Second}, {"0", time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), time.Second},
		{"600", 10 * time.Minute},
		{"9223372036854775807", time.Duration(1<<63 - 1)},
	} {
		require.Equal(t, tt.want, (&httpRejection{retryAfter: tt.header}).delay(time.Second, now), tt.header)
	}
}

func TestRuleAlertRetryCloseCancelsRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		e := retryTestExporter(t, func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		e.enqueueRuleAlertRetry([]byte("alert"), &httpRejection{status: 429})
		time.Sleep(time.Second)
		<-started
		require.NoError(t, e.Close())
		synctest.Wait()
		require.Zero(t, e.ruleRetries.items.Len())
	})
}

func TestRuleAlertRetryAfterBeyondRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return retryTestResponse(429, "600"), nil })
		e.SendRuleAlert(retryTestFailure())
		time.Sleep(ruleRetryRetention + time.Second)
		synctest.Wait()
		require.EqualValues(t, 1, calls.Load(), "must expire rather than retry before Retry-After")
		require.Zero(t, e.ruleRetries.items.Len())
	})
}

func TestRuleAlertRetryReleasesPayload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) { return retryTestResponse(200, ""), nil })
		e.enqueueRuleAlertRetry([]byte("retired"), &httpRejection{status: 503})
		synctest.Wait()
		q := e.ruleRetries
		q.mu.Lock()
		retired := q.items.Front()
		q.mu.Unlock()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		q.mu.Lock()
		defer q.mu.Unlock()
		require.Zero(t, q.items.Len())
		require.Zero(t, q.bytes)
		require.Nil(t, retired.Value, "retired queue element must release its payload")
	})
}

func TestRuleAlertRetryHTTP(t *testing.T) {
	var calls atomic.Int32
	delivered := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		delivered <- body
		w.WriteHeader(200)
	}))
	defer server.Close()
	e, err := NewHTTPExporter(HTTPExporterConfig{URL: server.URL}, "", "", nil, "", armotypes.AlertSourcePlatformK8sAgent)
	require.NoError(t, err)
	defer e.Close()
	e.SendRuleAlert(retryTestFailure())
	select {
	case body := <-delivered:
		require.Contains(t, string(body), "stable-alert-id")
	case <-time.After(5 * time.Second):
		t.Fatal("alert was not retried after HTTP 429")
	}
	require.NoError(t, e.Close())
	require.EqualValues(t, 2, calls.Load())
}

func TestRuleAlertRetryEndpointCooldownAndPacing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var attempts []time.Time
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) {
			mu.Lock()
			defer mu.Unlock()
			attempts = append(attempts, time.Now())
			if len(attempts) == 1 {
				return retryTestResponse(429, "60"), nil
			}
			return retryTestResponse(200, ""), nil
		})
		e.config.MaxAlertsPerMinute = 100
		e.SendRuleAlert(retryTestFailure())
		for i := 0; i < 5; i++ {
			e.SendRuleAlert(retryTestFailure())
		}
		synctest.Wait()
		time.Sleep(59 * time.Second)
		synctest.Wait()
		mu.Lock()
		count := len(attempts)
		mu.Unlock()
		require.Equal(t, 1, count, "new live alerts must respect endpoint cooldown")
		time.Sleep(5 * time.Second)
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		require.Len(t, attempts, 7)
		for i := 2; i < len(attempts); i++ {
			require.GreaterOrEqual(t, attempts[i].Sub(attempts[i-1]), time.Minute/100, "drain must be paced")
		}
	})
}

func TestRuleAlertRetryDrainStopsOnRejection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		e := retryTestExporter(t, func(*http.Request) (*http.Response, error) {
			n := calls.Add(1)
			if n == 1 {
				return retryTestResponse(429, "1"), nil
			}
			if n == 3 {
				return retryTestResponse(429, "60"), nil
			}
			return retryTestResponse(200, ""), nil
		})
		for i := 0; i < 5; i++ {
			e.SendRuleAlert(retryTestFailure())
		}
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 3, calls.Load())
		e.SendRuleAlert(retryTestFailure())
		time.Sleep(58 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 3, calls.Load(), "429 during drain must pause queued and live alerts")
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.EqualValues(t, 8, calls.Load())
	})
}
