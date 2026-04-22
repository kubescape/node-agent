package containerprofilecache

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
