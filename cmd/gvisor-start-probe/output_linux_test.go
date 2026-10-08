//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/gvisor"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestReceiverCancellationInterruptsFullOutputPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() // Keep the reader open throughout cancellation.
	defer writer.Close()
	fd := int(writer.Fd())
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETPIPE_SZ, 4096); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := unix.Write(fd, make([]byte, 4096))
		if err == unix.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Mimic inherited stdout, which starts as a blocking descriptor.
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	output, err := newJSONOutput(writer)
	if err != nil {
		t.Fatal(err)
	}
	defer output.file.Close()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.sock")
	entered := make(chan struct{})
	writeDone := make(chan error, 1)
	receiver := &gvisor.Receiver{
		SocketPath: path,
		Resolve:    func(id string) bool { return id == "known" },
		OnStart: func(ctx context.Context, start gvisor.Start) {
			close(entered)
			writeDone <- output.Encode(ctx, start)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
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
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("output callback did not start")
	}
	select {
	case err := <-writeDone:
		t.Fatalf("output did not block on the full pipe: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run remained blocked after cancellation with pipe reader open")
	}
	if err := <-writeDone; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked write was not interrupted by deadline: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("receiver socket remains after shutdown: %v", err)
	}
}

func TestJSONOutputWritesNormally(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "events")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	output, err := newJSONOutput(file)
	if err != nil {
		t.Fatal(err)
	}
	defer output.file.Close()
	for _, id := range []string{"first", "second", "third"} {
		if err := output.Encode(context.Background(), gvisor.Start{ContainerID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(file)
	for _, id := range []string{"first", "second", "third"} {
		var start gvisor.Start
		if err := decoder.Decode(&start); err != nil || start.ContainerID != id {
			t.Fatalf("normal output: got %q, want %q, err=%v", start.ContainerID, id, err)
		}
	}
}

func connectProbe(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if unix.Connect(fd, &unix.SockaddrUnix{Name: path}) == nil {
			timeout := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
				t.Fatal(err)
			}
			return fd
		}
		unix.Close(fd)
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("could not connect to probe receiver")
	return -1
}
