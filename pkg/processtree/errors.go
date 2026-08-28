package processtree

import "fmt"


type GetContainerSubtreeError struct {
	Err error
}

func (e *GetContainerSubtreeError) Error() string {
	return fmt.Sprintf("failed to get container subtree: %v", e.Err)
}

func (e *GetContainerSubtreeError) Unwrap() error {
	return e.Err
}
