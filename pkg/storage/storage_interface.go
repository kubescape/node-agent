package storage

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type StorageClient interface {
	CreateApplicationActivity(activity *v1beta1.ApplicationActivity, namespace string) error
	GetApplicationActivity(namespace, name string) (*v1beta1.ApplicationActivity, error)
	CreateApplicationProfile(profile *v1beta1.ApplicationProfile, namespace string) error
	PatchApplicationProfile(name, namespace string, patch []byte, channel chan error) error
	GetApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error)
	CreateApplicationProfileSummary(profile *v1beta1.ApplicationProfileSummary, namespace string) error
	CreateFilteredSBOM(SBOM *v1beta1.SBOMSyftFiltered) error
	GetFilteredSBOM(name string) (*v1beta1.SBOMSyftFiltered, error)
	GetSBOM(name string) (*v1beta1.SBOMSyft, error)
	IncrementImageUse(imageID string)
	DecrementImageUse(imageID string)
	GetNetworkNeighbors(namespace, name string) (*v1beta1.NetworkNeighbors, error)
	CreateNetworkNeighbors(networkNeighbors *v1beta1.NetworkNeighbors, namespace string) error
	PatchNetworkNeighborsMatchLabels(name, namespace string, networkNeighbors *v1beta1.NetworkNeighbors) error
	PatchNetworkNeighborsIngressAndEgress(name, namespace string, networkNeighbors *v1beta1.NetworkNeighbors) error
}
