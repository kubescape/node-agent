//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/kubescape/node-agent/pkg/gvisor"
	"golang.org/x/sys/unix"
)

type jsonOutput struct {
	file    *os.File
	encoder *json.Encoder
}

func newJSONOutput(output *os.File) (*jsonOutput, error) {
	// Inherited stdout may be a blocking pipe. Register a nonblocking duplicate
	// with Go's poller so a write deadline can interrupt a full pipe. The probe
	// owns stdout; the duplicate shares its nonblocking status with the original.
	fd, err := unix.FcntlInt(output.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "probe-output")
	return &jsonOutput{file: file, encoder: json.NewEncoder(file)}, nil
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
