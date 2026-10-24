//go:build experimental_signing

package containerprofilecache

import (
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// reportSpecDivergence warns when a signed object's STORED spec no longer
// matches its embedded signed content: what kubectl shows is not what is
// enforced, in either direction. Observability only — never part of the
// admission decision, and a comparison failure reports nothing. One warning
// per distinct stored content (re-armed when the divergence clears or the
// stored content changes again). Path names and counts only, never values.
func (c *ContainerProfileCacheImpl) reportSpecDivergence(key string, cp *v1beta1.ContainerProfile, bundleName, ns string) {
	paths, storedHash, ok := bundle.FragmentStoredDivergence(cp)
	if !ok {
		return
	}
	if len(paths) == 0 {
		c.specDivergence.Delete(key)
		return
	}
	if prev, loaded := c.specDivergence.Load(key); loaded && prev.(string) == storedHash {
		return
	}
	c.specDivergence.Store(key, storedHash)
	logger.L().Warning("signed fragment stored spec diverges from the signed content: the stored spec is display-only and is NOT enforced; enforcement uses the signed content",
		helpers.String("fragment", cp.Name),
		helpers.String("bundle", bundleName),
		helpers.String("namespace", ns),
		helpers.String("divergingPaths", strings.Join(paths, ",")),
		helpers.Int("pathCount", len(paths)),
		helpers.String("hint", "the object was edited after signing; re-apply the signed artifact to realign what kubectl shows with what is enforced"))
}
