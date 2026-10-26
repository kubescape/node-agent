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

func TestReceiverCountsInvalidFrameWithoutRetainingPayload(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	receiver := &Receiver{SocketPath: filepath.Join(dir, "events.sock"), Resolve: func(string) bool { return true }, OnStart: func(context.Context, Start) { t.Error("malformed frame delivered") }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fd := connectReceiver(t, receiver.SocketPath)
	sendPacket(t, fd, []byte{8, 1})
	if _, err := unix.Read(fd, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	const canary = "DIAGNOSTICS_MUST_NOT_RETAIN_THIS"
	sendPacket(t, fd, []byte(canary))
	unix.Close(fd)
	deadline := time.Now().Add(time.Second)
	for receiver.Stats().InvalidFrames == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stats := receiver.Stats()
	if stats.AcceptedConnections != 1 || stats.ClosedConnections != 1 || stats.Handshakes != 1 || stats.ReceivedFrames != 1 || stats.InvalidFrames != 1 || stats.VerifiedStarts != 0 || stats.CallbacksCompleted != 0 {
		t.Fatalf("unexpected counters: %+v", stats)
	}
	encoded, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Fatal("diagnostics retained frame contents")
	}
}

func TestReceiverReportsQueueLoss(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	receiver := &Receiver{SocketPath: filepath.Join(dir, "events.sock"), Resolve: func(string) bool { return true },
		OnStart: func(ctx context.Context, _ Start) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-ctx.Done()
		}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fd := connectReceiver(t, receiver.SocketPath)
	defer unix.Close(fd)
	sendPacket(t, fd, []byte{8, 1})
	if _, err := unix.Read(fd, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	sendPacket(t, fd, startFrame("known", "known", "private"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback not entered")
	}
	for range queueSize + 2 {
		sendPacket(t, fd, startFrame("known", "known", "private"))
	}
	deadline := time.Now().Add(time.Second)
	for receiver.Stats().QueueDrops < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stats := receiver.Stats()
	if stats.QueueDrops != 2 || stats.VerifiedStarts != queueSize+3 || stats.CallbacksCompleted != queueSize+1 {
		t.Fatalf("queue loss not accounted for: %+v", stats)
	}
}
