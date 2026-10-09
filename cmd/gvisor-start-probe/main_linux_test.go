//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProbeRestoresInheritedOutputFlags(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "gvisor-start-probe")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building probe: %v\n%s", err, output)
	}
	for _, mode := range []struct {
		name  string
		flags int
	}{{"blocking", 0}, {"nonblocking", unix.O_NONBLOCK}} {
		for _, failure := range []bool{false, true} {
			name := mode.name + "/signal_exit"
			if failure {
				name = mode.name + "/invalid_socket_directory"
			}
			t.Run(name, func(t *testing.T) {
				fds := make([]int, 2)
				if err := unix.Pipe2(fds, unix.O_CLOEXEC|mode.flags); err != nil {
					t.Fatal(err)
				}
				reader := os.NewFile(uintptr(fds[0]), "reader")
				writer := os.NewFile(uintptr(fds[1]), "writer")
				defer reader.Close()
				defer writer.Close()
				original, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "events.sock")
				if failure {
					path = filepath.Join(dir, "missing", "events.sock")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, "--socket", path, "--container-id", "known")
				cmd.Stdout = writer
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				if !failure {
					deadline := time.Now().Add(3 * time.Second)
					for {
						if _, err := os.Lstat(path); err == nil {
							break
						}
						if time.Now().After(deadline) {
							_ = cmd.Process.Kill()
							_ = cmd.Wait()
							t.Fatalf("probe did not create socket: %s", stderr.String())
						}
						time.Sleep(20 * time.Millisecond)
					}
					if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
						t.Fatal(err)
					}
				}
				err = cmd.Wait()
				if ctx.Err() != nil {
					t.Fatalf("probe did not exit: %v", ctx.Err())
				}
				if failure {
					if cmd.ProcessState.ExitCode() != 1 || stderr.Len() == 0 {
						t.Fatalf("expected receiver setup error: exit=%d stderr=%s", cmd.ProcessState.ExitCode(), stderr.String())
					}
				} else if err != nil {
					t.Fatalf("normal probe exit: %v\n%s", err, stderr.String())
				}
				after, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				if after != original {
					t.Fatalf("probe changed parent's output flags: before=%#x after=%#x", original, after)
				}
				if !failure {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("socket remains after exit: %v", err)
					}
				}
			})
		}
	}
}
