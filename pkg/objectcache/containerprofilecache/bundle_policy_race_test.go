//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"sync"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature/bundle"
)

// The trust policy is written by the reload goroutine and read on every
// reconciler tick; run with -race.
func TestSetBundleConfig_ConcurrentWithReaders(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	policies := []*bundle.TrustPolicy{
		nil,
		{Mode: bundle.ModeAlert},
		{Mode: bundle.ModeEnforce},
		{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{bundle.RuleClassBase: {}}},
	}

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				c.SetBundleConfig(policies[i%len(policies)])
			}
		}
	}()

	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 20000; i++ {
				_ = c.bundlesEnabled()
				_ = c.signingEnforced()
				_, _ = c.assembleUserBundle(context.Background(), "ns", "", "wlid")
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}
