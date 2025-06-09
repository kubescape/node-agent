package containerprofilemanager

import "errors"

var (
	ErrContainerNotFound        = errors.New("container not found")
	ContainerHasTerminatedError = errors.New("container has terminated")
	ContainerReachedMaxTime     = errors.New("container reached max time")

	// TODO: consider moving these to the storage package
	ObjectCompleted     = errors.New("object is completed")
	TooLargeObjectError = errors.New("object is too large")
)
