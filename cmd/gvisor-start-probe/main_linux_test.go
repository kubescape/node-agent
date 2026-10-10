//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestProbeRestoresInheritedOutputFlags(t *testing.T) {
	probeBinary := filepath.Join(t.TempDir(), "gvisor-start-probe")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", probeBinary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building probe: %v\n%s", err, output)
	}
	for _, mode := range []struct {
		name  string
		flags int
	}{{"blocking", 0}, {"nonblocking", unix.O_NONBLOCK}} {
		for _, scenario := range []string{"signal_exit", "invalid_socket_directory", "closed_output"} {
			name := mode.name + "/" + scenario
			t.Run(name, func(t *testing.T) {
				fds := make([]int, 2)
				if err := unix.Pipe2(fds, unix.O_CLOEXEC|mode.flags); err != nil {
					t.Fatal(err)
				}
				reader := os.NewFile(uintptr(fds[0]), "reader")
				writer := os.NewFile(uintptr(fds[1]), "writer")
				defer reader.Close()
				defer writer.Close()
				if scenario == "closed_output" {
					if err := reader.Close(); err != nil {
						t.Fatal(err)
					}
				}
				original, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "events.sock")
				if scenario == "invalid_socket_directory" {
					path = filepath.Join(dir, "missing", "events.sock")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, probeBinary, "--socket", path, "--container-id", "known")
				cmd.Stdout = writer
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				if scenario != "invalid_socket_directory" {
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
					if scenario == "closed_output" {
						client := connectProbe(t, path)
						handshake := protowire.AppendTag(nil, 1, protowire.VarintType)
						handshake = protowire.AppendVarint(handshake, 1)
						if _, err := unix.Write(client, handshake); err != nil {
							t.Fatal(err)
						}
						if _, err := unix.Read(client, make([]byte, 32)); err != nil {
							t.Fatal(err)
						}
						frame := make([]byte, 8)
						binary.LittleEndian.PutUint16(frame[:2], 8)
						binary.LittleEndian.PutUint16(frame[2:4], 1)
						frame = protowire.AppendTag(frame, 2, protowire.BytesType)
						frame = protowire.AppendString(frame, "known")
						if _, err := unix.Write(client, frame); err != nil {
							t.Fatal(err)
						}
						unix.Close(client)
					} else if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
						t.Fatal(err)
					}
				}
				err = cmd.Wait()
				if ctx.Err() != nil {
					t.Fatalf("probe did not exit: %v", ctx.Err())
				}
				if scenario != "signal_exit" {
					if cmd.ProcessState.ExitCode() != 1 || stderr.Len() == 0 {
						t.Fatalf("expected probe failure: exit=%d stderr=%s", cmd.ProcessState.ExitCode(), stderr.String())
					}
					if scenario == "closed_output" && !strings.Contains(stderr.String(), "gvisor start probe output:") {
						t.Fatalf("missing output failure diagnostic: %s", stderr.String())
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
				if scenario != "invalid_socket_directory" {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("socket remains after exit: %v", err)
					}
				}
			})
		}
	}
}
