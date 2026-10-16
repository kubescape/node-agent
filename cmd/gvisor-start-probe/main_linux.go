//go:build linux

// Command gvisor-start-probe is a controlled experiment for the SecCheck
// container/start point. It does not enable gVisor collection in node-agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/node-agent/pkg/gvisor"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	socket := flag.String("socket", "/run/kubescape/gvisor-events.sock", "private Unix socket for the SecCheck remote sink")
	containerID := flag.String("container-id", "", "exact container ID obtained independently from the local runtime before start")
	flag.Parse()
	if *containerID == "" {
		fmt.Fprintln(os.Stderr, "container-id is required")
		return 2
	}
	output, err := newJSONOutput(os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gvisor start probe output: %v\n", err)
		return 1
	}
	defer func() {
		if err := output.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "gvisor start probe output cleanup: %v\n", err)
			exitCode = 1
		}
	}()
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()
	outputErrors := make(chan error, 1)
	receiver := &gvisor.Receiver{
		SocketPath: *socket,
		Resolve: func(id string) bool {
			return id == *containerID
		},
		OnStart: func(ctx context.Context, start gvisor.Start) {
			if err := output.Encode(ctx, start); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
					(ctx.Err() != nil && errors.Is(err, os.ErrDeadlineExceeded)) {
					return
				}
				select {
				case outputErrors <- err:
				default:
				}
				cancel()
			}
		},
	}
	runErr := receiver.Run(ctx)
	select {
	case err := <-outputErrors:
		fmt.Fprintf(os.Stderr, "gvisor start probe output: %v\n", err)
		return 1
	default:
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "gvisor start probe: %v\n", runErr)
		return 1
	}
	return 0
}
