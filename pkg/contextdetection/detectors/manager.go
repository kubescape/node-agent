package detectors

import (
	"errors"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/contextdetection"
)

var (
	ErrInvalidContainer = errors.New("invalid container: nil provided")
)

type DetectorManager struct {
	registry  *contextdetection.MntnsRegistry
	detectors []contextdetection.ContextDetector
}

// NewDetectorManager creates a new DetectorManager with the given registry.
// Detectors are initialized in priority order: K8s (0), Host (1), Standalone (2).
func NewDetectorManager(registry *contextdetection.MntnsRegistry) *DetectorManager {
	dm := &DetectorManager{
		registry: registry,
		detectors: []contextdetection.ContextDetector{
			NewK8sDetector(),
			NewHostDetector(),
			NewStandaloneDetector(),
		},
	}

	return dm
}

// DetectContext detects the context of a container by running detectors in priority order.
// Returns the ContextInfo from the first detector that matches, or a default Standalone context
// if no detector matches.
func (dm *DetectorManager) DetectContext(container *containercollection.Container) (contextdetection.ContextInfo, error) {
	if container == nil {
		logger.L().Warning("DetectorManager - nil container provided")
		return nil, ErrInvalidContainer
	}

	containerID := container.Runtime.ContainerID
	logger.L().Debug("DetectorManager - detecting context for container",
		helpers.String("containerID", containerID))

	for _, detector := range dm.detectors {
		contextInfo, detected := detector.Detect(container)
		if detected {
			logger.L().Debug("DetectorManager - detected context",
				helpers.String("containerID", containerID),
				helpers.String("context", string(contextInfo.Context())),
				helpers.String("workloadID", contextInfo.WorkloadID()))
			return contextInfo, nil
		}
	}

	logger.L().Warning("DetectorManager - no detector matched, defaulting to Standalone",
		helpers.String("containerID", containerID))

	return &StandaloneContextInfo{
		ContainerID:   container.Runtime.ContainerID,
		ContainerName: container.Runtime.ContainerName,
	}, nil
}
