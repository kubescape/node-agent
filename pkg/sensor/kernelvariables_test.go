package sensor

import (
	"context"
	"fmt"
	"runtime"
	"testing"
)

func TestSenseProcSysKernel(t *testing.T) {

	// get OS type
	osVar := runtime.GOOS
	fmt.Printf("Tests are running over OS: %s.\n", osVar)

	switch osVar {
	case "windows":
		fmt.Printf("Tests are running over OS: %s. Not supported, skipping test %T", osVar, t)
		// TODO: need to add functionality for windows
	case "darwin":
		fmt.Printf("Tests are running over OS: %s. Not supported, skipping test", osVar)
		// TODO: need to add functionality for macos
	case "linux":
		_, err := SenseProcSysKernel(context.TODO())
		if err != nil {
			t.Errorf("%v", err)
		}
	default:
		fmt.Printf("Tests are running over OS: %s.\n", osVar)
	}
}
