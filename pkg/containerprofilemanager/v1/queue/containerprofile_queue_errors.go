package queue

import (
	"errors"
	"strings"

	"github.com/kubescape/storage/pkg/registry/file"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// failureKind describes how the queue should react to a failed profile creation.
type failureKind int

const (
	// failureRetryable means the failure may resolve on its own, so the item is requeued.
	failureRetryable failureKind = iota
	// failureTerminal means the profile can never be accepted, so learning ends for the container.
	failureTerminal
	// failureSplit means the payload was rejected by the transport for its size alone.
	// It says nothing about the aggregate, so learning must continue: the chunk is halved
	// and both halves are requeued.
	failureSplit
)

// classifyFailure maps an error returned by storage.ProfileCreator onto the queue's reaction.
//
// For failureTerminal it also returns the sentinel to hand to ErrorCallback, so that
// ContainerProfileManager.handleSaveProfileError can end learning with the right status.
// That contract applies to failureTerminal only: for failureSplit the raw error is returned
// for logging, and it must never reach ErrorCallback.
//
// Failures reach us in three shapes, all of which must be recognised:
//
//   - a wrapped sentinel, when storage is used as a library (errors.Is matches);
//   - a sentinel as the message of a k8s StatusError, when the apiserver relays it verbatim
//     (StatusError.Error() returns only the message, so a substring match is needed - storage
//     wraps the sentinel in a size-specific prefix on some paths);
//   - a bare HTTP 413 with a plain-text body, when storage's QueueManager rejects the request
//     on Content-Length before it ever reaches the registry. This carries no sentinel at all,
//     which is why it must be matched on the status code.
//
// The two sentinel checks run before the status-code check so that an authoritative sentinel
// always wins over a bare status code: a 413 whose body happens to relay ObjectTooLargeError
// is a genuine aggregate verdict and stays terminal.
func classifyFailure(err error) (failureKind, error) {
	if err == nil {
		return failureRetryable, nil
	}

	if matchesSentinel(err, file.ObjectTooLargeError) {
		return failureTerminal, file.ObjectTooLargeError
	}

	if matchesSentinel(err, file.ObjectCompletedError) {
		return failureTerminal, file.ObjectCompletedError
	}

	// A bare 413 is a transport rejection of one delta, not a verdict on the aggregate, so
	// the chunk is halved rather than the container abandoned. IsRequestEntityTooLargeError
	// matches on the status code alone, which is what makes this work against a plain-text body.
	if apierrors.IsRequestEntityTooLargeError(err) {
		return failureSplit, err
	}

	return failureRetryable, err
}

// matchesSentinel reports whether err carries the given storage sentinel, either as a
// wrapped error or as text in the message relayed by the apiserver.
//
// The substring fallback is deliberately restricted to *apierrors.StatusError: that's the
// only shape where the message is known to be a sentinel relayed verbatim by the apiserver
// (StatusError.Error() returns only the message, and storage wraps the sentinel in a
// size-specific prefix on some paths, so errors.Is alone can't match it). Applying
// strings.Contains to every error shape would let any error whose text happens to embed
// "object is too large" or "object is completed" - e.g. from a proxy or ingress - classify
// as terminal and end learning for the container, even though it isn't a real sentinel.
func matchesSentinel(err, sentinel error) bool {
	if errors.Is(err, sentinel) {
		return true
	}

	var statusErr *apierrors.StatusError
	if errors.As(err, &statusErr) {
		return strings.Contains(statusErr.ErrStatus.Message, sentinel.Error())
	}

	return false
}
