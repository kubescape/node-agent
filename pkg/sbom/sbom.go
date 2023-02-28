package sbom

import (
	"fmt"
	v1 "sniffer/pkg/sbom/v1"
	"sniffer/pkg/storageclient"
)

const (
	KeyAlreadyExist  = "KeyAlreadyExist"
	DataAlreadyExist = "DataAlreadyExist"
)

type SBOMStructure struct {
	storageClient SBOMStorageClient
	SBOMData      SBOMFormat
	firstReport   bool
}

type SBOMStorageClient struct {
	client storageclient.StorageClient
}

func CreateSBOMStorageClient(sc storageclient.StorageClient) *SBOMStructure {
	return &SBOMStructure{
		storageClient: SBOMStorageClient{
			client: sc,
		},
		SBOMData:    v1.CreateSBOMDataSPDXVersionV050rc1(),
		firstReport: true,
	}
}

func (sc *SBOMStructure) GetSBOM(imageID string) error {
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

func (sc *SBOMStructure) FilterSBOM(instanceID string, sbomFileRelevantMap map[string]bool) error {
	return sc.SBOMData.FilterSBOM(sbomFileRelevantMap)
}

func (sc *SBOMStructure) StoreFilterSBOM(instanceID string) error {
	if sc.firstReport || sc.SBOMData.IsNewRelevantSBOMDataExist() {
		data, err := sc.SBOMData.GetFilterSBOMInBytes()
		if err != nil {
			return err
		}
		err = sc.storageClient.client.PostData(instanceID, data)
		if err != nil {
			if err.Error() == KeyAlreadyExist {
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
	return fmt.Errorf(DataAlreadyExist)
}
