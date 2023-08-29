package storage

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type StorageClient interface {
	CreateFilteredSBOM(SBOM *v1beta1.SBOMSPDXv2p3Filtered) error
	GetSBOM(name string) (*v1beta1.SBOMSPDXv2p3, error)
	PatchFilteredSBOM(name string, SBOM *v1beta1.SBOMSPDXv2p3Filtered) error
	IncrementImageUse(imageID string)
	DecrementImageUse(imageID string)
}
