// Package profiles is a build-time stub of the full profile-adapter
// package landing in kubescape/node-agent#809. Returns nil adapters —
// upstream IsSigned short-circuits and the tamper path is dormant
// until #809 lands and replaces this file.
package profiles

import (
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func NewApplicationProfileAdapter(_ *v1beta1.ApplicationProfile) signature.Signable {
	return nil
}

func NewNetworkNeighborhoodAdapter(_ *v1beta1.NetworkNeighborhood) signature.Signable {
	return nil
}
