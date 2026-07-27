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
)

// classifyFailure maps an error returned by storage.ProfileCreator onto the queue's reaction.
//
// For terminal failures it also returns the sentinel to hand to ErrorCallback, so that
// ContainerProfileManager.handleSaveProfileError can end learning with the right status.
//
// Sentinels reach us in three shapes, all of which must be recognised:
//
//   - wrapped, when storage is used as a library (errors.Is matches);
//   - as the message of a k8s StatusError, when the apiserver relays the sentinel verbatim
//     (StatusError.Error() returns only the message, so a substring match is needed - storage
//     wraps the sentinel in a size-specific prefix on some paths);
//   - as an HTTP 413 with a plain-text body, when storage's QueueManager rejects the request
//     on Content-Length before it ever reaches the registry. This carries no sentinel at all,
//     which is why it must be matched on the status code.
func classifyFailure(err error) (failureKind, error) {
	if err == nil {
		return failureRetryable, nil
	}

	// QueueManager rejects oversized requests up front with 413 and a plain-text body, so
	// there is no Status object to carry a reason. IsRequestEntityTooLargeError matches on
	// the status code alone, which is what makes this work.
	if apierrors.IsRequestEntityTooLargeError(err) {
		return failureTerminal, file.ObjectTooLargeError
	}

	if matchesSentinel(err, file.ObjectTooLargeError) {
		return failureTerminal, file.ObjectTooLargeError
	}

	if matchesSentinel(err, file.ObjectCompletedError) {
		return failureTerminal, file.ObjectCompletedError
	}

	return failureRetryable, err
}

// matchesSentinel reports whether err carries the given storage sentinel, either as a
// wrapped error or as text in the message relayed by the apiserver.
func matchesSentinel(err, sentinel error) bool {
	return errors.Is(err, sentinel) || strings.Contains(err.Error(), sentinel.Error())
}
