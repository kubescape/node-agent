package cel

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

// TestCompileSelectorRules pins that the selector rules type-check against the
// real event object type: event.dstPodLabels is declared as a generic CEL map
// and must remain assignable to the was_selector_in_{ingress,egress} map param.
// Regression guard for the R0012 ingress rule that consumes the IG-enriched
// peer namespace + labels.
func TestCompileSelectorRules(t *testing.T) {
	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	c, err := NewCEL(objCache, config.Config{
		CelConfigCache: cache.FunctionCacheConfig{MaxSize: 1000, TTL: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewCEL: %v", err)
	}

	exprs := []string{
		`cp.was_selector_in_ingress(event.containerId, event.dstNamespace, event.dstPodLabels)`,
		`cp.was_selector_in_egress(event.containerId, event.dstNamespace, event.dstPodLabels)`,
		// The full R0012 ingress expression as bound in default-rules.yaml.
		`event.pktType == 'HOST' && !event.dstAddr.startsWith('127.') && !cp.was_address_in_ingress(event.containerId, event.dstAddr) && !cp.was_selector_in_ingress(event.containerId, event.dstNamespace, event.dstPodLabels)`,
	}
	for _, e := range exprs {
		if err := c.registerExpression(e); err != nil {
			t.Fatalf("expression failed to compile: %q\n%v", e, err)
		}
	}
}
