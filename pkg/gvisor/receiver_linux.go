//go:build linux

package gvisor

import (
	"context"
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
		for start := range starts {
			r.OnStart(start)
		}
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
		select {
		case slots <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-slots }()
				defer unix.Close(client)
				r.receive(runCtx, client, starts)
			}()
		default:
			unix.Close(client)
		}
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
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout) != nil {
		return
	}
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout) != nil {
		return
	}
	n, _, flags, _, err := unix.Recvmsg(fd, buffer, nil, 0)
	if err != nil || n == 0 || flags&unix.MSG_TRUNC != 0 || n > maxFrameSize {
		return
	}
	if _, err = handshakeVersion(buffer[:n]); err != nil {
		return
	}
	response := protowire.AppendTag(nil, 1, protowire.VarintType)
	response = protowire.AppendVarint(response, protocolVersion)
	if _, err = unix.SendmsgN(fd, response, nil, nil, 0); err != nil {
		return
	}
	for ctx.Err() == nil {
		n, _, flags, _, err = unix.Recvmsg(fd, buffer, nil, 0)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			continue
		}
		if err != nil || n == 0 {
			return
		}
		if flags&unix.MSG_TRUNC != 0 || n > maxFrameSize {
			return
		}
		start, ok, err := decodeStartFrame(buffer[:n], time.Now(), r.Resolve)
		if err == nil && ok {
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
