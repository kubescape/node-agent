//go:build linux

package gvisor

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadPacketRetriesSignalInterruption(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	receiver := &Receiver{}
	tid := make(chan int, 1)
	type result struct {
		data string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid <- unix.Gettid()
		buffer := make([]byte, 32)
		n, _, err := receiver.readPacket(ctx, fds[0], buffer)
		data := ""
		if n > 0 {
			data = string(buffer[:n])
		}
		done <- result{data, err}
	}()
	readerTID := <-tid
	deadline := time.Now().Add(time.Second)
	for receiver.Stats().InterruptedReads == 0 && time.Now().Before(deadline) {
		if err := unix.Tgkill(os.Getpid(), readerTID, unix.SIGURG); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if receiver.Stats().InterruptedReads == 0 {
		t.Fatal("test did not interrupt a blocking read")
	}
	if _, err := unix.Write(fds[1], []byte("after-signal")); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.data != "after-signal" {
			t.Fatalf("read lost after interruption: data=%q err=%v", result.data, result.err)
		}
	case <-ctx.Done():
		t.Fatal("read did not finish after valid packet")
	}
}

func TestReadPacketHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	receiver := &Receiver{}
	if _, _, err := receiver.readPacket(ctx, -1, nil); err != context.Canceled {
		t.Fatalf("got %v, want cancellation before I/O", err)
	}
}

func TestReadPacketSignalsDoNotExtendDeadline(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	receiver := &Receiver{}
	tid := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid <- unix.Gettid()
		_, _, err := receiver.readPacket(ctx, fds[0], make([]byte, 32))
		done <- err
	}()
	readerTID := <-tid
	limit := time.After(time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("read succeeded without a packet")
			}
			if receiver.Stats().InterruptedReads == 0 {
				t.Fatal("test did not interrupt read")
			}
			return
		case <-ticker.C:
			if err := unix.Tgkill(os.Getpid(), readerTID, unix.SIGURG); err != nil && err != unix.ESRCH {
				t.Fatal(err)
			}
		case <-limit:
			t.Fatal("signals extended the read deadline")
		}
	}
}
