//go:build linux

package gvisor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	maxConnections = 8
	queueSize      = 128
)

// Receiver is an experimental, opt-in SecCheck remote sink listener. It does
// not configure runsc or acquire its single Default trace session.
type Receiver struct {
	SocketPath string
	Resolve    Resolver
	OnStart    StartHandler

	queueDrops atomic.Uint64
	counters   receiverCounters
}

// QueueDrops counts locally discarded events when the consumer cannot keep up.
func (r *Receiver) QueueDrops() uint64 { return r.queueDrops.Load() }

// Run listens until ctx is canceled. The socket parent must already exist,
// belong to this process, and be private; no existing socket is unlinked.
func (r *Receiver) Run(ctx context.Context) error {
	if r.Resolve == nil || r.OnStart == nil || r.SocketPath == "" {
		return errors.New("gvisor receiver requires socket path, resolver, and handler")
	}
	if err := privateParent(filepath.Dir(r.SocketPath)); err != nil {
		return err
	}
	if _, err := os.Lstat(r.SocketPath); err == nil {
		return errors.New("gvisor socket path already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking gvisor socket path: %w", err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("creating gvisor socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: r.SocketPath}); err != nil {
		return fmt.Errorf("binding gvisor socket: %w", err)
	}
	defer os.Remove(r.SocketPath)
	if err := os.Chmod(r.SocketPath, 0600); err != nil {
		return fmt.Errorf("setting gvisor socket permissions: %w", err)
	}
	if err := unix.Listen(fd, maxConnections); err != nil {
		return fmt.Errorf("listening on gvisor socket: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("configuring gvisor listener: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)

	starts := make(chan Start, queueSize)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		r.deliverStarts(ctx, starts)
	}()

	var clients sync.WaitGroup
	slots := make(chan struct{}, maxConnections)
	defer func() {
		cancel()
		clients.Wait()
		close(starts)
		<-workerDone
	}()

	for {
		if runCtx.Err() != nil {
			return nil
		}
		client, _, acceptErr := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if acceptErr != nil {
			if acceptErr == unix.EINTR {
				continue
			}
			if acceptErr == unix.EAGAIN || acceptErr == unix.EWOULDBLOCK {
				select {
				case <-runCtx.Done():
					return nil
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			return fmt.Errorf("accepting gvisor connection: %w", acceptErr)
		}
		r.counters.AcceptedConnections.Add(1)
		select {
		case slots <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer r.counters.ClosedConnections.Add(1)
				defer func() { <-slots }()
				defer unix.Close(client)
				r.receive(runCtx, client, starts)
			}()
		default:
			r.counters.RejectedConnections.Add(1)
			r.counters.ClosedConnections.Add(1)
			unix.Close(client)
		}
	}
}

func (r *Receiver) deliverStarts(ctx context.Context, starts <-chan Start) {
	for start := range starts {
		// Use the caller's context: an internal listener error still drains
		// queued events, while caller cancellation interrupts the handler.
		r.OnStart(ctx, start)
		r.counters.CallbacksCompleted.Add(1)
	}
}

func privateParent(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("checking gvisor socket directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("gvisor socket directory must be private and owned by the receiver")
	}
	return nil
}

func (r *Receiver) receive(ctx context.Context, fd int, starts chan<- Start) {
	// The extra byte and MSG_TRUNC flag detect oversized seqpacket records.
	buffer := make([]byte, maxFrameSize+1)
	defer clear(buffer)
	timeout := unix.NsecToTimeval((2 * time.Second).Nanoseconds())
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout) != nil {
		r.counters.HandshakeErrors.Add(1)
		return
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, 2*time.Second)
	defer cancelHandshake()
	n, flags, err := r.readPacket(handshakeCtx, fd, buffer)
	if err != nil || n == 0 || flags&unix.MSG_TRUNC != 0 || n > maxFrameSize {
		r.counters.HandshakeErrors.Add(1)
		return
	}
	if _, err = handshakeVersion(buffer[:n]); err != nil {
		r.counters.HandshakeErrors.Add(1)
		return
	}
	response := protowire.AppendTag(nil, 1, protowire.VarintType)
	response = protowire.AppendVarint(response, protocolVersion)
	for {
		if handshakeCtx.Err() != nil {
			r.counters.HandshakeErrors.Add(1)
			return
		}
		_, err = unix.SendmsgN(fd, response, nil, nil, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			r.counters.HandshakeErrors.Add(1)
			return
		}
		break
	}
	r.counters.Handshakes.Add(1)
	cancelHandshake()
	for ctx.Err() == nil {
		n, flags, err = r.readPacket(ctx, fd, buffer)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			continue
		}
		if err != nil || n == 0 {
			if err != nil && ctx.Err() == nil {
				r.counters.ReadErrors.Add(1)
			}
			return
		}
		r.counters.ReceivedFrames.Add(1)
		if flags&unix.MSG_TRUNC != 0 || n > maxFrameSize {
			r.counters.InvalidFrames.Add(1)
			return
		}
		if n >= headerSize && int(binary.LittleEndian.Uint16(buffer[:2])) >= headerSize &&
			int(binary.LittleEndian.Uint16(buffer[:2])) <= n && binary.LittleEndian.Uint32(buffer[4:8]) != 0 {
			r.counters.SenderDropFrames.Add(1)
		}
		start, ok, err := decodeStartFrame(buffer[:n], time.Now(), func(id string) bool {
			known := r.Resolve(id)
			if !known {
				r.counters.UnresolvedStarts.Add(1)
			}
			return known
		})
		if err != nil {
			r.counters.InvalidFrames.Add(1)
		} else if !ok {
			r.counters.IgnoredFrames.Add(1)
		}
		if err == nil && ok {
			r.counters.VerifiedStarts.Add(1)
			select {
			case starts <- start:
			default:
				r.queueDrops.Add(1)
			}
		}
		// Raw bytes may include argv, cwd, and env. Never retain them across reads.
		clear(buffer[:n])
	}
}

// readPacket retries signal interruptions instead of discarding a healthy
// connection. SO_RCVTIMEO makes socket reads interruptible even with SA_RESTART.
// The context bounds retries; a handshake's absolute deadline is not reset by
// repeated signals. Idle reads retain the receiver's two-second polling bound.
func (r *Receiver) readPacket(ctx context.Context, fd int, buffer []byte) (int, int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		wait := 2 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, 0, context.DeadlineExceeded
			}
			if remaining < wait {
				wait = remaining
			}
		}
		timeout := unix.NsecToTimeval(wait.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return 0, 0, err
		}
		n, _, flags, _, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err == unix.EINTR {
			r.counters.InterruptedReads.Add(1)
			continue
		}
		return n, flags, err
	}
}
