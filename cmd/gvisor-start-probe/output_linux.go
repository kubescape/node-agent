//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/kubescape/node-agent/pkg/gvisor"
	"golang.org/x/sys/unix"
)

type jsonOutput struct {
	file      *os.File
	encoder   *json.Encoder
	fd        uintptr
	flags     int
	closeOnce sync.Once
	closeErr  error
}

func newJSONOutput(output *os.File) (*jsonOutput, error) {
	// Inherited stdout may be a blocking pipe. Register a nonblocking duplicate
	// with Go's poller so a write deadline can interrupt a full pipe. The probe
	// must restore the shared flags before exiting. SyscallConn avoids Fd(),
	// which can itself switch a Go-managed pipe back to blocking mode.
	raw, err := output.SyscallConn()
	if err != nil {
		return nil, err
	}
	var flags, fd int
	var setupErr error
	if err := raw.Control(func(original uintptr) {
		flags, setupErr = unix.FcntlInt(original, unix.F_GETFL, 0)
		if setupErr == nil {
			fd, setupErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
		}
	}); err != nil {
		return nil, err
	}
	if setupErr != nil {
		return nil, setupErr
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "probe-output")
	return &jsonOutput{file: file, encoder: json.NewEncoder(file), fd: uintptr(fd), flags: flags}, nil
}

// Close restores the inherited file description after all output has finished.
func (o *jsonOutput) Close() error {
	o.closeOnce.Do(func() {
		_, restoreErr := unix.FcntlInt(o.fd, unix.F_SETFL, o.flags)
		o.closeErr = errors.Join(restoreErr, o.file.Close())
	})
	return o.closeErr
}

func (o *jsonOutput) Encode(ctx context.Context, start gvisor.Start) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// Regular files do not support deadlines; pipes and sockets do.
		_ = o.file.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	err := o.encoder.Encode(start)
	if !stop() {
		<-interrupted
	}
	return err
}
