package containerprofilecache

import (
	"errors"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// verifyApplicationProfile returns true if the profile passes signature verification
// (or verification is disabled). Returns false and logs a warning/debug if it fails.
func (c *ContainerProfileCacheImpl) verifyApplicationProfile(ap *v1beta1.ApplicationProfile, ctx string) bool {
	if !c.cfg.EnableSignatureVerification {
		return true
	}
	if err := signature.VerifyObject(profiles.NewApplicationProfileAdapter(ap)); err != nil {
		if errors.Is(err, signature.ErrObjectNotSigned) {
			logger.L().Debug("ContainerProfileCache: "+ctx+" is not signed, skipping",
				helpers.String("name", ap.Name),
				helpers.String("namespace", ap.Namespace))
		} else {
			logger.L().Warning("ContainerProfileCache: "+ctx+" signature verification failed, skipping",
				helpers.String("name", ap.Name),
				helpers.String("namespace", ap.Namespace),
				helpers.Error(err))
		}
		return false
	}
	return true
}

// verifyNetworkNeighborhood returns true if the NN passes signature verification
// (or verification is disabled). Returns false and logs a warning/debug if it fails.
func (c *ContainerProfileCacheImpl) verifyNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, ctx string) bool {
	if !c.cfg.EnableSignatureVerification {
		return true
	}
	if err := signature.VerifyObject(profiles.NewNetworkNeighborhoodAdapter(nn)); err != nil {
		if errors.Is(err, signature.ErrObjectNotSigned) {
			logger.L().Debug("ContainerProfileCache: "+ctx+" is not signed, skipping",
				helpers.String("name", nn.Name),
				helpers.String("namespace", nn.Namespace))
		} else {
			logger.L().Warning("ContainerProfileCache: "+ctx+" signature verification failed, skipping",
				helpers.String("name", nn.Name),
				helpers.String("namespace", nn.Namespace),
				helpers.Error(err))
		}
		return false
	}
	return true
}
