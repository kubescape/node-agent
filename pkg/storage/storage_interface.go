package storage

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type StorageClient interface {
	CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error
	CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error)
	GetSBOMMeta(name string) (*v1beta1.SBOMSyft, error)
	ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error)
}
