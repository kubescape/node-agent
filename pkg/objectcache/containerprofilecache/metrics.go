package containerprofilecache

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// Kind labels for ReportContainerProfileLegacyLoad and related metrics.
const (
	kindApplication = "application"
	kindNetwork     = "network"

	completenessFull    = "full"
	completenessPartial = "partial"
)

// reportDeprecationWarn emits a one-shot WARN log for a user-authored legacy
// CRD (ApplicationProfile or NetworkNeighborhood) that was merged into the
// ContainerProfile. Dedup key is (kind, namespace, name, resourceVersion) so a
// single RV only logs once per process lifetime, even across many containers.
func (c *ContainerProfileCacheImpl) reportDeprecationWarn(kind, namespace, name, rv string, reason string) {
	key := fmt.Sprintf("%s|%s/%s@%s", kind, namespace, name, rv)
	if _, already := c.deprecationDedup.LoadOrStore(key, struct{}{}); already {
		return
	}
	logger.L().Warning("ContainerProfileCache - user-authored legacy profile merged (deprecated)",
		helpers.String("kind", kind),
		helpers.String("namespace", namespace),
		helpers.String("name", name),
		helpers.String("resourceVersion", rv),
		helpers.String("reason", reason))
}

// emitOverlayMetrics fires the per-kind completeness metric + deprecation WARN
// once per (kind, namespace, name, rv). Shared by addContainer's buildEntry
// and the reconciler's rebuildEntry so the two stay in lockstep.
func (c *ContainerProfileCacheImpl) emitOverlayMetrics(
	userAP *v1beta1.ApplicationProfile,
	userNN *v1beta1.NetworkNeighborhood,
	warnings []partialProfileWarning,
) {
	partialByKind := map[string]struct{}{}
	for _, w := range warnings {
		partialByKind[w.Kind] = struct{}{}
		c.metricsManager.ReportContainerProfileLegacyLoad(w.Kind, completenessPartial)
		c.reportDeprecationWarn(w.Kind, w.Namespace, w.Name, w.ResourceVersion,
			fmt.Sprintf("pod has containers missing from user CRD: %v", w.MissingContainers))
	}
	if userAP != nil {
		if _, partial := partialByKind[kindApplication]; !partial {
			c.metricsManager.ReportContainerProfileLegacyLoad(kindApplication, completenessFull)
		}
		c.reportDeprecationWarn(kindApplication, userAP.Namespace, userAP.Name, userAP.ResourceVersion,
			"user-authored ApplicationProfile merged into ContainerProfile")
	}
	if userNN != nil {
		if _, partial := partialByKind[kindNetwork]; !partial {
			c.metricsManager.ReportContainerProfileLegacyLoad(kindNetwork, completenessFull)
		}
		c.reportDeprecationWarn(kindNetwork, userNN.Namespace, userNN.Name, userNN.ResourceVersion,
			"user-authored NetworkNeighborhood merged into ContainerProfile")
	}
}
