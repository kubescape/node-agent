package containerprofilemanager

import (
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

// TestCalculateSniffingTime_RuntimeDetectionFlagsDoNotExtendWindow is a
// profile-lifecycle finalization investigation test.
//
// Host is meant to run indefinitely, but calculateSniffingTime (this file's
// neighbor, lifecycle.go:174) always arms a fixed-duration timer
// (handleContainerMaxTime -> notifyContainerEndOfLife -> deleteContainer,
// lifecycle.go:146-148,192-226) that unconditionally removes ANY container's
// entry -- host included -- from the profile manager once cfg.MaxSniffingTime
// elapses. The plan's mitigation hypothesis was that
// EnableRuntimeDetection/EnablePartialProfileGeneration already provide
// continuous-learning semantics that could be reused for host.
//
// This test proves that hypothesis FALSE: grep across
// pkg/containerprofilemanager/v1 shows the only reference to either flag is
// lifecycle.go:114, which gates whether PRE-RUNNING containers are ignored
// (an unrelated concern -- and one host doesn't even hit, since
// hostidentity.BuildHostWatchedContainerData sets PreRunningContainer=false).
// Neither flag is read anywhere in calculateSniffingTime,
// handleContainerMaxTime, or the timer setup in addContainerWithTimeout.
// Enabling both flags must not change the computed sniffing duration; if it
// did, that would indicate an undiscovered code path providing the mitigation
// this test set out to verify.
func TestCalculateSniffingTime_RuntimeDetectionFlagsDoNotExtendWindow(t *testing.T) {
	container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID: "host", ContainerName: "host",
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "host", PodName: "host-node-1",
			// No MaxSniffingTimeLabel pod label set: the only other input
			// calculateSniffingTime consults besides cfg.MaxSniffingTime.
		}},
	}

	baseCfg := config.Config{MaxSniffingTime: 24 * time.Hour, MaxJitterPercentage: 0}

	withoutFlags := &ContainerProfileManager{cfg: baseCfg}
	withoutFlagsTime := withoutFlags.calculateSniffingTime(container)

	withFlagsCfg := baseCfg
	withFlagsCfg.EnableRuntimeDetection = true
	withFlagsCfg.EnablePartialProfileGeneration = true
	withFlags := &ContainerProfileManager{cfg: withFlagsCfg}
	withFlagsTime := withFlags.calculateSniffingTime(container)

	assert.Equal(t, 24*time.Hour, withoutFlagsTime,
		"baseline: sniffing time is exactly cfg.MaxSniffingTime with no jitter and no pod-label override")
	assert.Equal(t, withoutFlagsTime, withFlagsTime,
		"EnableRuntimeDetection/EnablePartialProfileGeneration must NOT be read by calculateSniffingTime -- "+
			"if this fails, a mitigation exists and the finalization-risk finding needs updating")
}
