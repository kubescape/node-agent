//go:build linux

package gvisor

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func waitHealth(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("health condition did not become true")
}

func handshakeClient(t *testing.T, path string) int {
	t.Helper()
	fd := connectReceiver(t, path)
	t.Cleanup(func() { unix.Close(fd) })
	timeout := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	sendPacket(t, fd, []byte{8, 1})
	if _, err := unix.Read(fd, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return fd
}

func stopReceiver(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestReceiverReservesQueueSpaceForOtherConnections(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	delivered := make(chan Start, queueSize+1)
	var first atomic.Bool
	r := &Receiver{SocketPath: filepath.Join(dir, "events.sock"), Resolve: func(string) bool { return true },
		OnStart: func(ctx context.Context, s Start) {
			if first.CompareAndSwap(false, true) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return
				}
			}
			delivered <- s
		}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	flood := handshakeClient(t, r.SocketPath)
	sendPacket(t, flood, startFrame("flood", "flood", "private"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback not entered")
	}
	for range perConnectionQueue + 3 {
		sendPacket(t, flood, startFrame("flood", "flood", "private"))
	}
	waitHealth(t, func() bool { return r.Stats().QueueDrops == 3 })
	quiet := handshakeClient(t, r.SocketPath)
	sendPacket(t, quiet, startFrame("quiet", "quiet", "private"))
	waitHealth(t, func() bool { return r.Stats().VerifiedStarts == perConnectionQueue+5 })
	close(release)
	waitHealth(t, func() bool { return r.Stats().CallbacksCompleted == perConnectionQueue+2 })
	stopReceiver(t, cancel, done)
	quietCount := 0
	for len(delivered) > 0 {
		if (<-delivered).ContainerID == "quiet" {
			quietCount++
		}
	}
	s := r.Stats()
	if quietCount != 1 || s.QueueDrops != 3 || s.CanceledStarts != 0 || s.ActiveConnections != 0 || s.Listening {
		t.Fatalf("fair admission/lifecycle failed: %+v quiet=%d", s, quietCount)
	}
}

func TestReceiverRejectsBadClientsAndAcceptsReconnect(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan Start, 2)
	r := &Receiver{SocketPath: filepath.Join(dir, "events.sock"), Resolve: func(string) bool { return true }, OnStart: func(_ context.Context, s Start) { delivered <- s }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	bad := connectReceiver(t, r.SocketPath)
	sendPacket(t, bad, []byte{8, 99})
	unix.Close(bad)
	waitHealth(t, func() bool { return r.Stats().HandshakeErrors == 1 && r.Stats().ActiveConnections == 0 })
	large := handshakeClient(t, r.SocketPath)
	sendPacket(t, large, startFrame(strings.Repeat("x", maxIDSize+1), strings.Repeat("x", maxIDSize+1), "private"))
	waitHealth(t, func() bool { return r.Stats().InvalidFrames == 1 })
	if err := unix.Shutdown(large, unix.SHUT_RDWR); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, func() bool { return r.Stats().ActiveConnections == 0 })
	// A failed client does not terminate or reset cumulative receiver diagnostics.
	good := handshakeClient(t, r.SocketPath)
	frame := startFrame("known", "known", "private")
	binary.LittleEndian.PutUint32(frame[4:8], 7)
	sendPacket(t, good, frame)
	waitHealth(t, func() bool { return r.Stats().CallbacksCompleted == 1 })
	stopReceiver(t, cancel, done)
	s := r.Stats()
	if s.Handshakes != 2 || s.AcceptedConnections != 3 || s.ClosedConnections != 3 || s.SenderDropFrames != 2 {
		t.Fatalf("recovery counters: %+v", s)
	}
	// Closed connections are source health, never synthesized stop callbacks.
	if len(delivered) != 1 {
		t.Fatal("disconnect produced a lifecycle callback")
	}
	if _, err := os.Lstat(r.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket not removed: %v", err)
	}
	// A new process/instance can bind the cleaned path.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- r.Run(ctx2) }()
	handshakeClient(t, r.SocketPath)
	stopReceiver(t, cancel2, done2)
}

func TestReceiverConnectionLimitAndSlotRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r := &Receiver{SocketPath: filepath.Join(dir, "events.sock"), Resolve: func(string) bool { return true }, OnStart: func(context.Context, Start) {}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	fds := make([]int, 0, maxConnections)
	for range maxConnections {
		fds = append(fds, handshakeClient(t, r.SocketPath))
	}
	extra := connectReceiver(t, r.SocketPath)
	defer unix.Close(extra)
	waitHealth(t, func() bool { return r.Stats().RejectedConnections == 1 })
	// Shut down one established sender and use the freed admission slot.
	if err := unix.Shutdown(fds[0], unix.SHUT_RDWR); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, func() bool { return r.Stats().ActiveConnections == maxConnections-1 })
	handshakeClient(t, r.SocketPath)
	stopReceiver(t, cancel, done)
	if r.Stats().ActiveConnections != 0 || r.Stats().AcceptedConnections != r.Stats().ClosedConnections {
		t.Fatalf("connection leak: %+v", r.Stats())
	}
}

func TestCollectorRetriesWithoutReplacingExistingPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.sock")
	if err := os.WriteFile(path, []byte("not our socket"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Collector{retryDelay: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	lookup := func(_ context.Context, id string) (Identity, error) {
		return Identity{ContainerID: id, SandboxID: "sandbox", Namespace: "ns", PodName: "pod", PodUID: "uid", ContainerName: "app", RuntimeHandler: "runsc"}, nil
	}
	go func() {
		done <- c.Run(ctx, IntegrationConfig{Enabled: true, SocketPath: path}, "node", lookup, func(context.Context, Observation) {})
	}()
	waitHealth(t, func() bool { return c.Stats().ListenerFailures > 0 })
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "not our socket" {
		t.Fatal("recovery replaced an existing path")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fd := handshakeClient(t, path)
	sendPacket(t, fd, startFrame("known", "known", "private"))
	waitHealth(t, func() bool { return c.Stats().ExportSubmitted == 1 })
	stopReceiver(t, cancel, done)
	h := c.Stats()
	if h.Running || h.Receiver.Listening || h.RecheckRejected != 0 || h.Receiver.CallbacksCompleted != 1 {
		t.Fatalf("health: %+v", h)
	}
}

func TestCollectorRetryWaitHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "occupied")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	c := new(Collector)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, IntegrationConfig{Enabled: true, SocketPath: path}, "node", func(context.Context, string) (Identity, error) { return Identity{}, nil }, func(context.Context, Observation) {})
	}()
	waitHealth(t, func() bool { return c.Stats().ListenerFailures == 1 })
	stopReceiver(t, cancel, done)
	if c.Stats().ListenerFailures != 1 {
		t.Fatal("retry wait ignored cancellation")
	}
}

func TestCollectorRecoversAfterLookupFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := new(Collector)
	var calls atomic.Int32
	lookup := func(_ context.Context, id string) (Identity, error) {
		if calls.Add(1) == 1 {
			return Identity{}, context.DeadlineExceeded
		}
		return Identity{ContainerID: id, SandboxID: "sandbox", Namespace: "ns", PodName: "pod", PodUID: "uid", ContainerName: "app", RuntimeHandler: "runsc"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	path := filepath.Join(dir, "events.sock")
	go func() {
		done <- c.Run(ctx, IntegrationConfig{Enabled: true, SocketPath: path}, "node", lookup, func(context.Context, Observation) {})
	}()
	fd := handshakeClient(t, path)
	sendPacket(t, fd, startFrame("known", "known", "private"))
	waitHealth(t, func() bool { return c.Stats().Receiver.UnresolvedStarts == 1 })
	sendPacket(t, fd, startFrame("known", "known", "private"))
	waitHealth(t, func() bool { return c.Stats().ExportSubmitted == 1 })
	stopReceiver(t, cancel, done)
	h := c.Stats()
	if h.Receiver.Handshakes != 1 || h.ListenerFailures != 0 || h.Receiver.ReceivedFrames != 2 || h.Receiver.VerifiedStarts != 1 || h.RecheckRejected != 0 {
		t.Fatalf("lookup recovery: %+v", h)
	}
}
