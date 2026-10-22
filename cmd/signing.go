//go:build experimental_signing

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/healthmanager"
	"github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	rulebindingcachev1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleswatcher"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
)

const signedClusterDataPath = "/etc/config/clusterData.signed.json"

func materialiseVerifiedClusterData(verified []byte) (string, error) {
	dir, err := os.MkdirTemp("", "node-agent-clusterdata-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "clusterData.json")
	if err := os.WriteFile(path, verified, 0600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

func verifiedClusterDataPath() (string, func(), error) {
	verified, signed, err := bundle.LoadSignedConfigIfPresent(signedClusterDataPath)
	if err != nil {
		return "", func() {}, err
	}
	if !signed {
		return "/etc/config/clusterData.json", func() {}, nil
	}
	path, err := materialiseVerifiedClusterData(verified)
	if err != nil {
		return "", func() {}, err
	}
	return path, func() { _ = os.RemoveAll(filepath.Dir(path)) }, nil
}
func configureSigningHealth(h *healthmanager.HealthManager) {
	h.SetPolicyStatus(bundle.PolicyStatusSnapshot)
}
func configureSigning(ctx context.Context, cfg config.Config, cpc *containerprofilecache.ContainerProfileCacheImpl, rulesWatcher *ruleswatcher.RulesWatcherImpl, ruleBindingCache *rulebindingcachev1.RBCache, exporter exporters.Exporter) {
	cpc.SetTamperAlertExporter(exporter)
	if cfg.BundleTrustPolicyPath != "" {
		// The root anchor is resolved ONLY from the fixed mount or the
		// compiled default, never from a config-supplied path, so editing
		// the (mutable) node-agent ConfigMap cannot redirect the anchor.
		var prevPolicy *bundle.TrustPolicy
		applyTrustPolicy := func(policy *bundle.TrustPolicy, rootFp string, mounted bool, resync bool) {
			cpc.SetBundleConfig(policy)
			if policy.Enforcing() {
				logger.L().Info("signed bundle overlays enabled in ENFORCE mode: unsigned and unverifiable artifacts are refused")
			} else {
				logger.L().Info("signed bundle overlays enabled in alert mode")
			}
			if mounted {
				logger.L().Warning("signed bundle overlays anchored to a MOUNTED root public key: the trust anchor is cluster-mutable, protect it with an immutable ConfigMap and tight RBAC", helpers.String("fingerprint", rootFp))
			} else if bundle.IsDemoRoot(rootFp) {
				logger.L().Warning("signed bundle overlays anchored to the PUBLISHED DEMO root key: this authenticates nothing, mount a real root before relying on signatures")
			}
			// The same trust policy also governs signed Rules fragments; at
			// boot this runs before dWatcher.Start, so the watcher has not
			// yet synced anything; SetTrustPolicy is mutex-guarded regardless.
			if rulesWatcher != nil {
				rulesWatcher.SetTrustPolicy(policy)
				if policy.RuleSigningEnabled() {
					logger.L().Info("signed rule fragments enabled")
				}
				if resync {
					rulesWatcher.ResyncNow(ctx)
				}
			}
			if !policy.RuleSigningEnabled() {
				logger.L().Warning("rule signing DISABLED: the trust policy in force carries no ruleClasses; ANY Rules object in ANY namespace will load without a signature check")
			}
			if bundle.RuleAdmissionUnauthenticated(policy, rootFp) {
				logger.L().Warning("trust policy configures rule signing but the trust anchor is the published demo root key: rule admission is NOT authenticated; mount a real root before relying on signed rules")
			}
			if ruleBindingCache != nil {
				ruleBindingCache.SetTrustPolicy(policy)
				if policy.BindingSigningEnabled() {
					logger.L().Info("signed rule bindings enabled")
				}
				if resync {
					// Bindings re-check admission on their next binding
					// event, not on reload — documented limitation.
					logger.L().Info("rule bindings re-evaluate under the reloaded policy on their next binding event")
				}
			}
			if prevPolicy != nil {
				ruleOff := prevPolicy.RuleSigningEnabled() && !policy.RuleSigningEnabled()
				bindOff := prevPolicy.BindingSigningEnabled() && !policy.BindingSigningEnabled()
				modeDown := prevPolicy.Enforcing() && !policy.Enforcing()
				if ruleOff || bindOff || modeDown {
					logger.L().Warning("trust policy reloaded with REDUCED scope",
						helpers.String("ruleSigning", fmt.Sprintf("%v->%v", prevPolicy.RuleSigningEnabled(), policy.RuleSigningEnabled())),
						helpers.String("bindingSigning", fmt.Sprintf("%v->%v", prevPolicy.BindingSigningEnabled(), policy.BindingSigningEnabled())),
						helpers.String("mode", fmt.Sprintf("%s->%s", prevPolicy.EffectiveMode(), policy.EffectiveMode())))
				}
			}
			prevPolicy = policy
		}

		// The reloader runs whether or not the boot load succeeded: a bad
		// mounted policy must not require a restart to recover from, and
		// crash-looping instead would hand ConfigMap writers a fleet-wide
		// kill switch. An invalid boot policy leaves signing DISABLED
		// (scream-and-poll) until a verifiable artifact is mounted.
		// Startup uses the same single-read verification path as later reloads.
		// The in-force policy and digest therefore describe the same artifact,
		// even if kubelet swaps the ConfigMap while startup is running.
		reloader := bundle.NewPolicyReloader(cfg.BundleTrustPolicyPath, nil, 0)
		boot := reloader.Poll()
		if boot.Err != nil {
			logger.L().Warning("trust policy invalid at startup: signed bundle overlays DISABLED until a valid policy is mounted; re-checking every reload interval",
				helpers.String("path", cfg.BundleTrustPolicyPath), helpers.Error(boot.Err))
		} else if boot.Applied != nil {
			applyTrustPolicy(boot.Applied, boot.RootFP, boot.Mounted, false)
			bundle.SetInForcePolicy(boot.Applied, boot.ArtifactDigest, boot.RootFP, boot.Mounted)
			logger.L().Info("trust policy in force", helpers.String("inForceDigest", boot.ArtifactDigest), helpers.String("mode", string(boot.Applied.EffectiveMode())))
		}
		go reloader.Watch(ctx, bundle.DefaultPolicyReloadInterval, func(ev bundle.PolicyReloadEvent) {
			if ev.Err != nil {
				bundle.RecordPolicyRefusal(ev.ArtifactDigest)
				logger.L().Error("trust policy reload REFUSED: keeping the policy already in force",
					helpers.String("refusedDigest", ev.ArtifactDigest),
					helpers.String("inForceDigest", ev.InForceDigest),
					helpers.String("rootFingerprint", ev.RootFP),
					helpers.String("hint", "the mounted ConfigMap now contains the REFUSED artifact; what the cluster shows is not what is enforced until a verifiable policy is applied"),
					helpers.Error(ev.Err))
				return
			}
			if ev.Applied == nil {
				return
			}
			applyTrustPolicy(ev.Applied, ev.RootFP, ev.Mounted, true)
			bundle.SetInForcePolicy(ev.Applied, ev.ArtifactDigest, ev.RootFP, ev.Mounted)
			ruleSigning := "off"
			if ev.Applied.RuleSigningEnabled() {
				ruleSigning = "on"
			}
			logger.L().Info("trust policy reloaded without restart",
				helpers.String("inForceDigest", ev.ArtifactDigest),
				helpers.String("mode", string(ev.Applied.EffectiveMode())),
				helpers.String("ruleSigning", ruleSigning),
				helpers.Int("ruleClasses", len(ev.Applied.RuleClasses)),
				helpers.Int("bindingClasses", len(ev.Applied.BindingClasses)))
		})
	}
}
