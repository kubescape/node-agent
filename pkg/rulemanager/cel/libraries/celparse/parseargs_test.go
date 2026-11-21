package celparse

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type badSizeLister struct {
	traits.Lister
}

func (b badSizeLister) Size() ref.Val {
	return types.String("invalid-size")
}

func (b badSizeLister) ConvertToNative(_ reflect.Type) (any, error) { return nil, nil }
func (b badSizeLister) ConvertToType(_ ref.Type) ref.Val            { return nil }
func (b badSizeLister) Equal(_ ref.Val) ref.Val                     { return types.False }
func (b badSizeLister) Type() ref.Type                              { return types.ListType }
func (b badSizeLister) Value() any                                  { return nil }

func TestParseList_Success(t *testing.T) {
	strList := types.DefaultTypeAdapter.NativeToValue([]string{"alpha", "beta", "gamma"})
	gotStrings, err := ParseList[string](strList)
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "beta", "gamma"}, gotStrings)

	emptyList := types.DefaultTypeAdapter.NativeToValue([]string{})
	gotEmpty, err := ParseList[string](emptyList)
	require.NoError(t, err)
	assert.Empty(t, gotEmpty)

	intList := types.DefaultTypeAdapter.NativeToValue([]int64{10, 20, 30})
	gotInts, err := ParseList[int64](intList)
	require.NoError(t, err)
	assert.Equal(t, []int64{10, 20, 30}, gotInts)
}

func TestParseList_Errors(t *testing.T) {
	// Non-list value
	_, err := ParseList[string](types.String("not-a-list"))
	var listErr *CELListError
	require.ErrorAs(t, err, &listErr)
	assert.Equal(t, "invalid list format: expected list", listErr.Error())

	// Invalid size type
	_, err = ParseList[string](badSizeLister{})
	require.ErrorAs(t, err, &listErr)
	assert.Equal(t, "invalid list size type", listErr.Error())

	// Mixed element types in list
	mixedList := types.DefaultTypeAdapter.NativeToValue([]any{"valid", int64(42)})
	_, err = ParseList[string](mixedList)
	require.ErrorAs(t, err, &listErr)
	assert.Equal(t, "invalid element type in list at index 1", listErr.Error())
}
