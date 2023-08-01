package sbom

import (
	"context"
	"errors"
	v1 "node-agent/pkg/sbom/v1"
	"node-agent/pkg/storageclient"

	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/k8s-interface/names"
	"github.com/spf13/afero"
)

const (
	DataAlreadyExist = "already exist"
)

type SBOMStructure struct {
	storageClient SBOMStorageClient
	SBOMData      v1.SBOMFormat
	firstReport   bool
	wlid          string
	instanceID    instanceidhandler.IInstanceID
}

var _ SBOMClient = (*SBOMStructure)(nil)

type SBOMStorageClient struct {
	client storageclient.StorageClient
}

var errorsOfSBOM map[string]error

func init() {
	errorsOfSBOM = make(map[string]error)
	errorsOfSBOM[DataAlreadyExist] = errors.New(DataAlreadyExist)
}

func CreateSBOMStorageClient(sc storageclient.StorageClient, wlid string, instanceID instanceidhandler.IInstanceID, sbomFs afero.Fs) *SBOMStructure {
	return &SBOMStructure{
		storageClient: SBOMStorageClient{
			client: sc,
		},
		SBOMData:    v1.CreateSBOMDataSPDXVersionV040(instanceID, sbomFs),
		firstReport: true,
		instanceID:  instanceID,
		wlid:        wlid,
	}
}

func (sc *SBOMStructure) GetSBOM(ctx context.Context, imageTag, imageID string) error {

	if sc.SBOMData.IsSBOMAlreadyExist() {
		return nil
	}

	SBOMKey, err := names.ImageInfoToSlug(imageTag, imageID)
	if err != nil {
		return err
	}

	SBOM, err := sc.storageClient.client.GetData(SBOMKey)
	if err != nil {
		return err
	}
	err = sc.SBOMData.StoreSBOM(ctx, SBOM)
	if err != nil {
		return err
	}
	return nil
}

func (sc *SBOMStructure) IsSBOMAlreadyExist() bool {
	return sc.SBOMData.IsSBOMAlreadyExist()
}

func (sc *SBOMStructure) FilterSBOM(sbomFileRelevantMap map[string]bool) error {
	return sc.SBOMData.FilterSBOM(sbomFileRelevantMap)
}

func (sc *SBOMStructure) StoreFilterSBOM(imageID, instanceID string) error {
	if sc.firstReport || sc.SBOMData.IsNewRelevantSBOMDataExist() {
		sc.SBOMData.SetFilteredSBOMName(instanceID)
		sc.SBOMData.StoreMetadata(sc.wlid, imageID, sc.instanceID)
		data := sc.SBOMData.GetFilterSBOMData()
		err := sc.storageClient.client.PostData(data)
		if err != nil {
			if storageclient.IsAlreadyExist(err) {
				data = sc.SBOMData.GetFilterSBOMData()
				err = sc.storageClient.client.PutData(instanceID, data)
				if err != nil {
					return err
				}
			}
		}
		if err == nil {
			sc.firstReport = false
		}
		return err
	}
	return errorsOfSBOM[DataAlreadyExist]
}

func (sc *SBOMStructure) CleanResources() {
	sc.SBOMData.CleanResources()
}

func IsAlreadyExist() error {
	return errorsOfSBOM[DataAlreadyExist]
}

func (sc *SBOMStructure) ValidateSBOM(ctx context.Context) error {
	return sc.SBOMData.ValidateSBOM(ctx)
}
