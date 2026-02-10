package testutils

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

func RunCommand(name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exiterr *exec.ExitError
		if errors.As(err, &exiterr) {
			if stderr.Len() > 0 {
				fmt.Printf("Command '%s %v' failed: %s\n", name, args, stderr.String())
			}
			return exiterr.ExitCode()
		}
	}
	return 0
}
