package storage

import (
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type StorageClient interface {
	CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error
	PatchApplicationProfile(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error
	GetContainerProfile(namespace, name string) (*v1beta1.ContainerProfile, error)
	CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error)
	GetSBOM(name string) (*v1beta1.SBOMSyft, error)
	GetSBOMMeta(name string) (*v1beta1.SBOMSyft, error)
	ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error)
	IncrementImageUse(imageID string)
	DecrementImageUse(imageID string)
	GetNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error)
	CreateNetworkNeighborhood(neighborhood *v1beta1.NetworkNeighborhood, namespace string) error
	PatchNetworkNeighborhood(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error
}
