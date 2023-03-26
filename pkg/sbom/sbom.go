package sbom

import (
	"errors"
	v1 "sniffer/pkg/sbom/v1"
	"sniffer/pkg/storageclient"
)

const (
	DataAlreadyExist = "already exist"
)

type SBOMStructure struct {
	storageClient SBOMStorageClient
	SBOMData      SBOMFormat
	firstReport   bool
	wlid          string
	instanceID    string
}

type SBOMStorageClient struct {
	client storageclient.StorageClient
}

var errorsOfSBOM map[string]error

func init() {
	errorsOfSBOM = make(map[string]error)
	errorsOfSBOM[DataAlreadyExist] = errors.New(DataAlreadyExist)
}

func CreateSBOMStorageClient(sc storageclient.StorageClient, wlid, instanceID string) *SBOMStructure {
	return &SBOMStructure{
		storageClient: SBOMStorageClient{
			client: sc,
		},
		SBOMData:    v1.CreateSBOMDataSPDXVersionV040(),
		firstReport: true,
		wlid:        wlid,
		instanceID:  instanceID,
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
		sc.SBOMData.StoreMetadata(sc.wlid, sc.instanceID)
		data := sc.SBOMData.GetFilterSBOMData()
		err := sc.storageClient.client.PostData(instanceID, data)
		if err != nil {
			if storageclient.IsAlreadyExist(err) {
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
