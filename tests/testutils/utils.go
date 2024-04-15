package testutils

import (
	"fmt"
	"io"
	"os/exec"
)

func RunCommand(name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			return exiterr.ExitCode()
		} else {
			panic(fmt.Sprintf("cmd.Wait: %v", err))
		}
	}
	return 0
}
