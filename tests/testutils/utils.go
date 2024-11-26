package testutils

import (
	"errors"
	"io"
	"os/exec"
)

func RunCommand(name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		var exiterr *exec.ExitError
		if errors.As(err, &exiterr) {
			return exiterr.ExitCode()
		}
	}
	return 0
}
