package sbom

import (
	"errors"
	v1 "sniffer/pkg/sbom/v1"
	"sniffer/pkg/storageclient"

	instanceidhandler "github.com/kubescape/k8s-interface/instanceidhandler"
)

const (
	DataAlreadyExist = "already exist"
)

type SBOMStructure struct {
	storageClient SBOMStorageClient
	SBOMData      SBOMFormat
	firstReport   bool
	imageID       string
	wlid          string
	instanceID    instanceidhandler.IInstanceID
}

type SBOMStorageClient struct {
	client storageclient.StorageClient
}

var errorsOfSBOM map[string]error

func init() {
	errorsOfSBOM = make(map[string]error)
	errorsOfSBOM[DataAlreadyExist] = errors.New(DataAlreadyExist)
}

func CreateSBOMStorageClient(sc storageclient.StorageClient, wlid, imageID string, instanceID instanceidhandler.IInstanceID) *SBOMStructure {
	return &SBOMStructure{
		storageClient: SBOMStorageClient{
			client: sc,
		},
		SBOMData:    v1.CreateSBOMDataSPDXVersionV040(),
		firstReport: true,
		instanceID:  instanceID,
		wlid:        wlid,
		imageID:     imageID,
	}
}

func (sc *SBOMStructure) GetSBOM(imageID string) error {
	if sc.SBOMData.IsSBOMAlreadyExist() {
		return nil
	}

	SBOM, err := sc.storageClient.client.GetData(imageID)
	if err != nil {
		return err
	}
	err = sc.SBOMData.StoreSBOM(SBOM)
	if err != nil {
		return err
	}
	return nil
}

func (sc *SBOMStructure) FilterSBOM(sbomFileRelevantMap map[string]bool) error {
	return sc.SBOMData.FilterSBOM(sbomFileRelevantMap)
}

func (sc *SBOMStructure) StoreFilterSBOM(instanceID string) error {
	if sc.firstReport || sc.SBOMData.IsNewRelevantSBOMDataExist() {
		sc.SBOMData.StoreFilteredSBOMName(instanceID)
		sc.SBOMData.StoreMetadata(sc.wlid, sc.imageID, sc.instanceID)
		data := sc.SBOMData.GetFilterSBOMData()
		err := sc.storageClient.client.PostData(instanceID, data)
		if err != nil {
			if storageclient.IsAlreadyExist(err) {
				sc.SBOMData.AddResourceVersionIfNeeded(sc.storageClient.client.GetResourceVersion(instanceID))
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

func IsAlreadyExist() error {
	return errorsOfSBOM[DataAlreadyExist]
}
