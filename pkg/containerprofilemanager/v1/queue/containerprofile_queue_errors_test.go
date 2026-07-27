package queue

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// genericStatusError reproduces what client-go builds when the response body is not a
// Status object, which is what storage's QueueManager returns for an oversized request.
func genericStatusError(code int) error {
	return apierrors.NewGenericServerResponse(
		code, "POST",
		schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "containerprofiles"},
		"cattle-cluster-agent", "", 0, false,
	)
}

// relayedStatusError reproduces what client-go builds when the apiserver relays a plain
// (non-Status) error from the storage registry: the message is carried verbatim.
func relayedStatusError(message string) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusInternalServerError,
		Reason:  metav1.StatusReasonUnknown,
		Message: message,
	}}
}

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantKind     failureKind
		wantSentinel error
	}{
		{
			name:     "nil error is not a failure",
			err:      nil,
			wantKind: failureRetryable,
		},
		{
			// The ISO Gruppe regression: QueueManager rejects on Content-Length with a
			// plain-text 413, so the error carries neither sentinel.
			name:         "http 413 from QueueManager is terminal and reported as too large",
			err:          genericStatusError(http.StatusRequestEntityTooLarge),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			name:         "wrapped ObjectTooLargeError is terminal",
			err:          fmt.Errorf("saving profile: %w", file.ObjectTooLargeError),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			name:         "bare ObjectTooLargeError relayed by the apiserver is terminal",
			err:          relayedStatusError(file.ObjectTooLargeError.Error()),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			// storage prefixes the sentinel with the limit on the application-profile and
			// network-neighborhood paths, so exact string equality is not enough.
			name:         "prefixed ObjectTooLargeError relayed by the apiserver is terminal",
			err:          relayedStatusError("application profile size exceeds the limit of 40000: object is too large"),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			name:         "bare ObjectCompletedError relayed by the apiserver is terminal",
			err:          relayedStatusError(file.ObjectCompletedError.Error()),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectCompletedError,
		},
		{
			name:         "wrapped ObjectCompletedError is terminal",
			err:          fmt.Errorf("saving profile: %w", file.ObjectCompletedError),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectCompletedError,
		},
		{
			name:     "server timeout is retryable",
			err:      relayedStatusError("the server has received too many requests and has asked us to try again later"),
			wantKind: failureRetryable,
		},
		{
			name:     "connection refused is retryable",
			err:      errors.New("dial tcp 10.96.0.1:443: connect: connection refused"),
			wantKind: failureRetryable,
		},
		{
			name:     "conflict is retryable",
			err:      genericStatusError(http.StatusConflict),
			wantKind: failureRetryable,
		},
		{
			name:     "internal server error is retryable",
			err:      genericStatusError(http.StatusInternalServerError),
			wantKind: failureRetryable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, reported := classifyFailure(tt.err)
			assert.Equal(t, tt.wantKind, kind)

			if tt.wantKind == failureTerminal {
				// The sentinel is what ContainerProfileManager.handleSaveProfileError
				// matches on to pick the terminal container status.
				assert.Equal(t, tt.wantSentinel, reported)
			} else {
				assert.Equal(t, tt.err, reported)
			}
		})
	}
}

// TestClassifyFailure_413IsNotRequeued guards the specific regression: before this fix a
// 413 matched neither sentinel by string equality and was requeued forever.
func TestClassifyFailure_413IsNotRequeued(t *testing.T) {
	err := genericStatusError(http.StatusRequestEntityTooLarge)

	// Establish that the old exact-equality check really does miss this error, so the
	// test fails loudly if someone reintroduces it.
	assert.NotEqual(t, file.ObjectTooLargeError.Error(), err.Error())
	assert.NotEqual(t, file.ObjectCompletedError.Error(), err.Error())

	kind, reported := classifyFailure(err)
	assert.Equal(t, failureTerminal, kind)
	assert.Equal(t, file.ObjectTooLargeError, reported)
}

// alwaysFailingCreator returns the same error for every create and counts the calls.
type alwaysFailingCreator struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (c *alwaysFailingCreator) CreateContainerProfileDirect(*v1beta1.ContainerProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.err
}

func (c *alwaysFailingCreator) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// recordingCallback captures the errors the queue reports through ErrorCallback.
type recordingCallback struct {
	mu     sync.Mutex
	errors []error
}

func (r *recordingCallback) OnQueueError(_ *v1beta1.ContainerProfile, _ string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, err)
}

func (r *recordingCallback) captured() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errors...)
}

func startQueue(t *testing.T, creator *alwaysFailingCreator, cb ErrorCallback, maxAttempts int) *QueueData {
	t.Helper()

	qd, err := NewQueueData(context.Background(), creator, QueueConfig{
		QueueName:       "test-queue",
		QueueDir:        t.TempDir(),
		MaxQueueSize:    10,
		MaxAttempts:     maxAttempts,
		RetryInterval:   20 * time.Millisecond,
		ItemsPerSegment: 10,
		ErrorCallback:   cb,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qd.Close() })

	qd.Start()
	return qd
}

func testProfile() *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cattle-cluster-agent", Namespace: "cattle-system"},
	}
}

// TestQueueEndsLearningOnHTTP413 is the regression test for the ISO Gruppe report: an
// oversized profile rejected by storage's QueueManager must end learning instead of being
// retried every RetryInterval forever.
func TestQueueEndsLearningOnHTTP413(t *testing.T) {
	creator := &alwaysFailingCreator{err: genericStatusError(http.StatusRequestEntityTooLarge)}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, DefaultMaxAttempts)

	require.NoError(t, qd.Enqueue(testProfile(), "container-id"))

	// The item is consumed once and reported as too large.
	assert.Eventually(t, func() bool {
		return len(cb.captured()) == 1
	}, 2*time.Second, 10*time.Millisecond, "expected the profile to be reported through OnQueueError")

	assert.Equal(t, []error{file.ObjectTooLargeError}, cb.captured(),
		"the sentinel must be reported so the manager sets status=too-large and ends learning")
	assert.Equal(t, 0, qd.GetQueueSize(), "the rejected profile must not stay in the queue")

	// Give the processor several more ticks to prove there is no retry loop.
	callsAfterReport := creator.callCount()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, callsAfterReport, creator.callCount(), "a 413 must not be retried")
	assert.Equal(t, 1, creator.callCount(), "the profile must be attempted exactly once")
}

// TestQueueDropsProfileAfterMaxAttempts covers the general case: any error that never
// resolves must stop consuming the queue rather than starving newer profiles.
func TestQueueDropsProfileAfterMaxAttempts(t *testing.T) {
	const maxAttempts = 3

	creator := &alwaysFailingCreator{err: errors.New("dial tcp 10.96.0.1:443: connect: connection refused")}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, maxAttempts)

	require.NoError(t, qd.Enqueue(testProfile(), "container-id"))

	assert.Eventually(t, func() bool {
		return creator.callCount() >= maxAttempts && qd.GetQueueSize() == 0
	}, 2*time.Second, 10*time.Millisecond, "expected the profile to be dropped after %d attempts", maxAttempts)

	// The retry budget is a hard bound, so no further attempts happen.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, maxAttempts, creator.callCount(), "attempts must be capped at MaxAttempts")
	assert.Equal(t, 0, qd.GetQueueSize())
	assert.Empty(t, cb.captured(), "a retryable failure must not end learning for the container")
}

// TestNewQueueDataDefaultsMaxAttempts pins the default so an unset config cannot restore
// the unbounded-retry behaviour.
func TestNewQueueDataDefaultsMaxAttempts(t *testing.T) {
	for _, configured := range []int{0, -1} {
		qd, err := NewQueueData(context.Background(), &alwaysFailingCreator{}, QueueConfig{
			QueueName:       "test-queue",
			QueueDir:        t.TempDir(),
			ItemsPerSegment: 10,
			MaxAttempts:     configured,
		})
		require.NoError(t, err)
		assert.Equal(t, DefaultMaxAttempts, qd.maxAttempts)
		require.NoError(t, qd.Close())
	}
}
