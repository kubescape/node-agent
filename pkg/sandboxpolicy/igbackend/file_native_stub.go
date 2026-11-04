//go:build !file_runtime

package igbackend

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"oras.land/oras-go/v2"
)

// NewNativeFileEngine is not available until the file runtime package is in
// the tree (see file_native.go).
func NewNativeFileEngine(runtime.Runtime, operators.DataOperator, oras.ReadOnlyTarget, string) (FileEngine, error) {
	return nil, fmt.Errorf("this build has no file gadget runtime")
}
