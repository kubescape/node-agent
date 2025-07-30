package applicationprofile

import (
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// CELListError represents an error that occurred while parsing a CEL list
type CELListError struct {
	Message string
}

func (e *CELListError) Error() string {
	return e.Message
}

// ParseList parses a CEL list into a Go slice of the specified type
func ParseList[T any](list ref.Val) ([]T, error) {
	argsList, ok := list.(traits.Lister)
	if !ok {
		return nil, &CELListError{Message: "invalid list format: expected list"}
	}

	sizeVal := argsList.Size()
	size, ok := sizeVal.Value().(int64)
	if !ok {
		return nil, &CELListError{Message: "invalid list size type"}
	}

	result := make([]T, size)
	for i := int64(0); i < size; i++ {
		val := argsList.Get(types.Int(i))
		typedVal, ok := val.Value().(T)
		if !ok {
			return nil, &CELListError{Message: fmt.Sprintf("invalid element type in list at index %d", i)}
		}
		result[i] = typedVal
	}

	return result, nil
}
