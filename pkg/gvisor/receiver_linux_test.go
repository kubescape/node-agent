//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestReceiverVerifiesIdentityAndDropsSensitiveFields(t *testing.T) {
	const canary = "synthetic-argv-secret"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.sock")
	starts := make(chan Start, 1)
	receiver := &Receiver{
		SocketPath: path,
		Resolve:    func(id string) bool { return id == "known-container" },
		OnStart:    func(_ context.Context, start Start) { starts <- start },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fd := connectReceiver(t, path)
	defer unix.Close(fd)
	timeout := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}

	handshake := protowire.AppendTag(nil, 1, protowire.VarintType)
	handshake = protowire.AppendVarint(handshake, 1)
	sendPacket(t, fd, handshake)
	buffer := make([]byte, 32)
	if _, err := unix.Read(fd, buffer); err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	sendPacket(t, fd, startFrame("unknown-container", "unknown-container", canary))
	sendPacket(t, fd, startFrame("known-container", "known-container", canary))
	select {
	case start := <-starts:
		if start.ContainerID != "known-container" || start.Source != "gvisor_trace" {
			t.Fatalf("unexpected start: %+v", start)
		}
		encoded, err := json.Marshal(start)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("secret retained: %s", encoded)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("verified start did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("receiver did not stop")
	}
}

func TestReceiverKeepsConcurrentConnectionsSeparate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.sock")
	starts := make(chan Start, 40)
	receiver := &Receiver{
		SocketPath: path,
		Resolve:    func(id string) bool { return id == "first" || id == "second" },
		OnStart:    func(_ context.Context, start Start) { starts <- start },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fds := make(map[string]int)
	for _, id := range []string{"first", "second"} {
		fd := connectReceiver(t, path)
		fds[id] = fd
		handshake := protowire.AppendTag(nil, 1, protowire.VarintType)
		handshake = protowire.AppendVarint(handshake, 1)
		sendPacket(t, fd, handshake)
		buffer := make([]byte, 32)
		if _, err := unix.Read(fd, buffer); err != nil {
			t.Fatal(err)
		}
	}
	for range 20 {
		for _, id := range []string{"first", "second"} {
			sendPacket(t, fds[id], startFrame(id, id, "private"))
		}
	}
	for _, fd := range fds {
		unix.Close(fd)
	}
	counts := map[string]int{}
	deadline := time.After(4 * time.Second)
	for len(starts) > 0 || counts["first"]+counts["second"] < 40 {
		select {
		case event := <-starts:
			counts[event.ContainerID]++
		case <-deadline:
			t.Fatalf("missing events: %v", counts)
		}
	}
	if counts["first"] != 20 || counts["second"] != 20 {
		t.Fatalf("connections crossed or lost identity: %v", counts)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("receiver did not stop")
	}
}

func TestReceiverDrainsClosedQueue(t *testing.T) {
	starts := make(chan Start, 3)
	for _, id := range []string{"first", "second", "third"} {
		starts <- Start{ContainerID: id}
	}
	close(starts)
	var delivered []string
	receiver := &Receiver{OnStart: func(ctx context.Context, start Start) {
		if ctx.Err() != nil {
			t.Fatal("normal queue drain received a canceled context")
		}
		delivered = append(delivered, start.ContainerID)
	}}
	receiver.deliverStarts(context.Background(), starts)
	if strings.Join(delivered, ",") != "first,second,third" {
		t.Fatalf("queue did not drain in order: %v", delivered)
	}
}

func connectReceiver(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Connect(fd, &unix.SockaddrUnix{Name: path}); err == nil {
			return fd
		}
		unix.Close(fd)
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("could not connect to receiver")
	return -1
}

func sendPacket(t *testing.T, fd int, packet []byte) {
	t.Helper()
	if _, err := unix.SendmsgN(fd, packet, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
}
