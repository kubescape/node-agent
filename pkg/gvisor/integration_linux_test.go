//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGVisorIntegrationVerifiesBeforeQueueAndExport(t *testing.T) {
	for _, mode := range []string{"verified", "unknown", "disappeared", "canceled_lookup"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := IntegrationConfig{Enabled: true, SocketPath: filepath.Join(dir, "starts.sock")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			lookup := func(ctx context.Context, id string) (Identity, error) {
				n := calls.Add(1)
				if mode == "canceled_lookup" {
					<-ctx.Done()
					return Identity{}, ctx.Err()
				}
				if mode == "unknown" || (mode == "disappeared" && n > 1) {
					return Identity{}, errors.New("unknown")
				}
				return Identity{ContainerID: id, SandboxID: "sandbox", Namespace: "apps", PodName: "pod", PodUID: "uid", ContainerName: "app", RuntimeHandler: "runsc"}, nil
			}
			emitted := make(chan Observation, 1)
			done := make(chan error, 1)
			go func() {
				done <- RunIntegration(ctx, cfg, "node", lookup, func(_ context.Context, o Observation) { emitted <- o })
			}()
			fd := connectReceiver(t, cfg.SocketPath)
			defer unix.Close(fd)
			sendPacket(t, fd, []byte{8, 1})
			if _, err := unix.Read(fd, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
			sendPacket(t, fd, startFrame("known", "known", "SECRET_ARG_AND_CWD"))
			deadline := time.Now().Add(time.Second)
			for calls.Load() < 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if mode == "verified" {
				select {
				case got := <-emitted:
					data, err := json.Marshal(got)
					if err != nil || strings.Contains(string(data), "SECRET_ARG_AND_CWD") {
						t.Fatal("sensitive fields retained in observation")
					}
					if got.Source != "gvisor_trace" || got.Identity.ContainerID != "known" || got.Node != "node" || calls.Load() != 2 {
						t.Fatalf("incorrect verified observation: %+v", got)
					}
				case <-time.After(time.Second):
					t.Fatal("verified start not emitted")
				}
			} else {
				if mode == "disappeared" {
					deadline := time.Now().Add(time.Second)
					for calls.Load() < 2 && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
					if calls.Load() != 2 {
						t.Fatal("dispatch did not recheck identity")
					}
				}
				time.Sleep(30 * time.Millisecond)
				select {
				case <-emitted:
					t.Fatal("unresolved start exported")
				default:
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("lookup/shutdown ignored cancellation")
			}
		})
	}
}

func TestGVisorIntegrationDisabledDoesNoIO(t *testing.T) {
	if err := RunIntegration(context.Background(), IntegrationConfig{}, "", nil, nil); err != nil {
		t.Fatal(err)
	}
}
