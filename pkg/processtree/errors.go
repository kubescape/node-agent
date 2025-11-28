package processtree

import "fmt"

type ProcessNotFoundError struct {
	Pid         uint32
	ContainerID string
}

func (e *ProcessNotFoundError) Error() string {
	return fmt.Sprintf("process with PID %d not found in container %s", e.Pid, e.ContainerID)
}

type GetProcessNodeError struct {
	Err error
}

func (e *GetProcessNodeError) Error() string {
	return fmt.Sprintf("failed to get process node: %v", e.Err)
}

func (e *GetProcessNodeError) Unwrap() error {
	return e.Err
}

type GetContainerSubtreeError struct {
	Err error
}

func (e *GetContainerSubtreeError) Error() string {
	return fmt.Sprintf("failed to get container subtree: %v", e.Err)
}

func (e *GetContainerSubtreeError) Unwrap() error {
	return e.Err
}
