//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
)

// TestDefaultBuildRegistersNoVerdictReceiver: the product build adds no
// receiver, so the exporter keeps counting every verdict as dropped.
func TestDefaultBuildRegistersNoVerdictReceiver(t *testing.T) {
	if withVerdictLog(nil) != nil {
		t.Fatal("nil receivers replaced")
	}
	receivers := maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	if got := withVerdictLog(receivers); got != receivers || got.Len() != 0 {
		t.Fatal("default build registered a receiver")
	}
	exporter, err := sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 1, Receivers: receivers})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exporter.Run(ctx) }()
	if err := exporter.ReportVerdict(ctx, sandboxpolicy.Verdict{ContainerID: "container", CgroupID: 19}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for exporter.Stats().Dropped == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("exporter Run: %v", err)
	}
	if s := exporter.Stats(); s.Dropped != 1 || s.Delivered != 0 {
		t.Fatalf("stats %+v", s)
	}
}
