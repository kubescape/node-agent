//go:build linux

// Command gvisor-start-probe is a controlled experiment for the SecCheck
// container/start point. It does not enable gVisor collection in node-agent.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/node-agent/pkg/gvisor"
)

func main() {
	socket := flag.String("socket", "/run/kubescape/gvisor-events.sock", "private Unix socket for the SecCheck remote sink")
	containerID := flag.String("container-id", "", "exact container ID obtained independently from the local runtime before start")
	flag.Parse()
	if *containerID == "" {
		fmt.Fprintln(os.Stderr, "container-id is required")
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	receiver := &gvisor.Receiver{
		SocketPath: *socket,
		Resolve: func(id string) bool {
			return id == *containerID
		},
		OnStart: func(start gvisor.Start) {
			_ = encoder.Encode(start)
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := receiver.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "gvisor start probe: %v\n", err)
		os.Exit(1)
	}
}
