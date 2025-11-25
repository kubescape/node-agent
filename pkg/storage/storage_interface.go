package storage

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
)

type ProfileClient interface {
	GetApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error)
	GetNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error)
	ListApplicationProfiles(namespace string) (*v1beta1.ApplicationProfileList, error)
	ListNetworkNeighborhoods(namespace string) (*v1beta1.NetworkNeighborhoodList, error)
}

// ProfileCreator defines the interface for creating container profiles
type ProfileCreator interface {
	CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error
}

type SbomClient interface {
	CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error)
	GetSBOMMeta(name string) (*v1beta1.SBOMSyft, error)
	ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error)
}

type StorageClient interface {
	GetStorageClient() spdxv1beta1.SpdxV1beta1Interface
}
