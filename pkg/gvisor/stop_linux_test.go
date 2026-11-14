//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stopSocketPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "events.sock")
}

func handshaken(t *testing.T, path string) int {
	t.Helper()
	fd := connectReceiver(t, path)
	sendPacket(t, fd, []byte{8, 1})
	if _, err := unix.Read(fd, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return fd
}

// Replays the record sequence seen for a normal exit with a child in #1091:
// sandbox start, workload start, child exit, init exit, parent notification,
// then the pause container's exit.
func TestReceiverReportsOneStopPerVerifiedInitialTask(t *testing.T) {
	const canary = "stop-trial-canary"
	path := stopSocketPath(t)
	stops := make(chan Stop, 4)
	receiver := &Receiver{
		SocketPath: path,
		Resolve:    func(id string) bool { return id == "app" }, // the sandbox ID is not a CRI container
		OnStart:    func(context.Context, Start) {},
		OnStop:     func(_ context.Context, stop Stop) { stops <- stop },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fd := handshaken(t, path)
	for _, frame := range [][]byte{
		keyedStartFrame("sandbox", 1, 50, canary),
		keyedStartFrame("app", 2, 100, canary),
		exitFrameBytes(taskExitMessage, "app", 3, 3, 150, 0),
		exitFrameBytes(exitNotifyParentMessage, "app", 3, 3, 150, 0),
		exitFrameBytes(taskExitMessage, "app", 2, 2, 100, 7<<8),
		exitFrameBytes(exitNotifyParentMessage, "app", 2, 2, 100, 7<<8),
		exitFrameBytes(taskExitMessage, "sandbox", 1, 1, 50, 9),
	} {
		sendPacket(t, fd, frame)
	}
	select {
	case stop := <-stops:
		if stop.ContainerID != "app" || stop.ExitCode != 7 || stop.Signal != 0 || stop.Source != "gvisor_trace" || stop.Dropped != 2 {
			t.Fatalf("unexpected stop: %+v", stop)
		}
		encoded, _ := json.Marshal(stop)
		if strings.Contains(string(encoded), "canary") {
			t.Fatalf("private fields retained: %s", encoded)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not arrive")
	}
	waitHealth(t, func() bool { return receiver.Stats().DuplicateTerminals == 1 && receiver.Stats().NonterminalExits == 3 })
	unix.Close(fd)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stats := receiver.Stats()
	if len(stops) != 0 || stats.VerifiedStops != 1 || stats.StopCallbacksCompleted != 1 || stats.UnobservedTerminations != 0 {
		t.Fatalf("unexpected stop accounting: %+v", stats)
	}
}

// A Sentry failure or a receiver restart closes the connection without any
// terminal record. That must be counted as loss, never reported as a stop.
func TestDisconnectIsCountedAsUnobservedNotStopped(t *testing.T) {
	path := stopSocketPath(t)
	receiver := &Receiver{
		SocketPath: path,
		Resolve:    func(string) bool { return true },
		OnStart:    func(context.Context, Start) {},
		OnStop:     func(context.Context, Stop) { t.Error("stop inferred from a closed connection") },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fd := handshaken(t, path)
	sendPacket(t, fd, keyedStartFrame("first", 2, 100, "x"))
	sendPacket(t, fd, keyedStartFrame("second", 3, 200, "x"))
	sendPacket(t, fd, startFrame("legacy", "legacy", "x")) // no start-time field
	waitHealth(t, func() bool { return receiver.Stats().VerifiedStarts == 3 })
	unix.Close(fd)
	waitHealth(t, func() bool { return receiver.Stats().UnobservedTerminations == 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if stats := receiver.Stats(); stats.VerifiedStops != 0 || stats.StopKeyMissing != 1 {
		t.Fatalf("unexpected accounting: %+v", stats)
	}
}

func TestExitPointsAreIgnoredWhenStopsAreDisabled(t *testing.T) {
	path := stopSocketPath(t)
	receiver := &Receiver{SocketPath: path, Resolve: func(string) bool { return true }, OnStart: func(context.Context, Start) {}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	fd := handshaken(t, path)
	sendPacket(t, fd, keyedStartFrame("app", 2, 100, "x"))
	sendPacket(t, fd, exitFrameBytes(taskExitMessage, "app", 2, 2, 100, 0))
	waitHealth(t, func() bool { return receiver.Stats().IgnoredFrames == 1 })
	unix.Close(fd)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if stats := receiver.Stats(); stats.VerifiedStops != 0 || stats.UnobservedTerminations != 0 || stats.NonterminalExits != 0 {
		t.Fatalf("stop state kept while disabled: %+v", stats)
	}
}

func TestCollectorRechecksStopsBeforeExport(t *testing.T) {
	for _, mode := range []string{"verified", "pod_gone"} {
		t.Run(mode, func(t *testing.T) {
			cfg := IntegrationConfig{Enabled: true, SocketPath: stopSocketPath(t), StopObservations: true}
			identity := func(id string) Identity {
				return Identity{ContainerID: id, SandboxID: "sandbox", Namespace: "apps", PodName: "pod", PodUID: "uid", ContainerName: "app", RuntimeHandler: "runsc"}
			}
			emitted := make(chan StopObservation, 1)
			collector := &Collector{
				StopLookup: func(_ context.Context, id string) (Identity, error) {
					if mode == "pod_gone" {
						return Identity{}, errors.New("gone")
					}
					return identity(id), nil
				},
				EmitStop: func(_ context.Context, o StopObservation) { emitted <- o },
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- collector.Run(ctx, cfg, "node", func(_ context.Context, id string) (Identity, error) { return identity(id), nil },
					func(context.Context, Observation) {})
			}()
			fd := handshaken(t, cfg.SocketPath)
			defer unix.Close(fd)
			sendPacket(t, fd, keyedStartFrame("app", 2, 100, "x"))
			sendPacket(t, fd, exitFrameBytes(taskExitMessage, "app", 2, 2, 100, 9))
			waitHealth(t, func() bool { return collector.Stats().Receiver.StopCallbacksCompleted == 1 })
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			health := collector.Stats()
			if mode == "verified" {
				got := <-emitted
				if got.Identity.PodUID != "uid" || got.Node != "node" || got.ExitCode != 137 || got.Signal != 9 || health.StopExportSubmitted != 1 {
					t.Fatalf("unexpected stop export: %+v %+v", got, health)
				}
			} else if len(emitted) != 0 || health.StopRecheckRejected != 1 {
				t.Fatalf("unverified stop exported: %+v", health)
			}
		})
	}
}

func TestStopObservationsRequireTerminalLookup(t *testing.T) {
	cfg := IntegrationConfig{Enabled: true, SocketPath: "/run/kubescape/x.sock", StopObservations: true}
	err := new(Collector).Run(context.Background(), cfg, "node",
		func(context.Context, string) (Identity, error) { return Identity{}, nil }, func(context.Context, Observation) {})
	if err == nil {
		t.Fatal("stop observations enabled without a terminal lookup")
	}
}
