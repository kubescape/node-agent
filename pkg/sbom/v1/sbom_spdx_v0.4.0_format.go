package sbom

import (
	"encoding/json"

	"github.com/spdx/tools-golang/spdx/common"
	spdx "github.com/spdx/tools-golang/spdx/v2_3"
)

const (
	// CreatorType should be one of "Person", "Organization", or "Tool"
	Organization              = "Organization"
	Tool                      = "Tool"
	Person                    = "Person"
	KubescapeOrganizationName = "Kubescape"
	KubescapeNodeAgentName    = "KubescapeNodeAgent"
	RelationshipContainType   = "CONTAINS"
)

type SBOMData struct {
	spdxData                              spdx.Document
	filteredSpdxData                      spdx.Document
	relevantRealtimeFilesBySPDXIdentifier map[common.ElementID]bool
	newRelevantData                       bool
}

func CreateSBOMDataSPDXVersionV050rc1() *SBOMData {
	return &SBOMData{
		filteredSpdxData:                      spdx.Document{},
		relevantRealtimeFilesBySPDXIdentifier: make(map[common.ElementID]bool),
		newRelevantData:                       false,
	}
}

func (sbom *SBOMData) StoreSBOM(sbomData []byte) error {
	err := json.Unmarshal(sbomData, &sbom.spdxData)
	if err != nil {
		return err
	}

	for i := range sbom.spdxData.Files {
		sbom.relevantRealtimeFilesBySPDXIdentifier[sbom.spdxData.Files[i].FileSPDXIdentifier] = false
	}
	sbom.filteredSpdxData = sbom.spdxData
	sbom.spdxData.CreationInfo.Creators = append(sbom.spdxData.CreationInfo.Creators, []common.Creator{
		{
			CreatorType: Organization,
			Creator:     KubescapeOrganizationName,
		},
		{
			CreatorType: Tool,
			Creator:     KubescapeNodeAgentName,
		},
	}...)

	sbom.filteredSpdxData.Files = make([]*spdx.File, 0)
	sbom.filteredSpdxData.Packages = make([]*spdx.Package, 0)
	sbom.filteredSpdxData.Relationships = make([]*spdx.Relationship, 0)

	return nil
}

func (sbom *SBOMData) FilterSBOM(sbomFileRelevantMap map[string]bool) error {
	sbom.newRelevantData = false
	//filter relevant file list
	for i := range sbom.spdxData.Files {
		if exist := sbomFileRelevantMap[sbom.spdxData.Files[i].FileName]; exist {
			if alreadyExist := sbom.relevantRealtimeFilesBySPDXIdentifier[sbom.spdxData.Files[i].FileSPDXIdentifier]; !alreadyExist {
				sbom.filteredSpdxData.Files = append(sbom.filteredSpdxData.Files, sbom.spdxData.Files[i])
				sbom.relevantRealtimeFilesBySPDXIdentifier[sbom.spdxData.Files[i].FileSPDXIdentifier] = true
				sbom.newRelevantData = true
			}
		}
	}

	//filter relevant package list
	for i := range sbom.spdxData.Packages {
		relevantFilesInPackage := make([]*spdx.File, 0)
		for j := range sbom.spdxData.Packages[i].Files {
			if exist := sbom.relevantRealtimeFilesBySPDXIdentifier[sbom.spdxData.Packages[i].Files[j].FileSPDXIdentifier]; exist {
				relevantFilesInPackage = append(relevantFilesInPackage, sbom.spdxData.Packages[i].Files[j])
			}
		}
		if len(relevantFilesInPackage) > 0 {
			relevantPackage := sbom.spdxData.Packages[i]
			relevantPackage.Files = relevantFilesInPackage
			sbom.filteredSpdxData.Packages = append(sbom.filteredSpdxData.Packages, relevantPackage)
		}
	}

	//filter relationship list
	for i := range sbom.spdxData.Relationships {
		switch sbom.spdxData.Relationships[i].Relationship {
		case RelationshipContainType:
			if exist := sbom.relevantRealtimeFilesBySPDXIdentifier[sbom.spdxData.Relationships[i].RefB.ElementRefID]; exist {
				sbom.filteredSpdxData.Relationships = append(sbom.filteredSpdxData.Relationships, sbom.spdxData.Relationships[i])
			}
		default:
			sbom.filteredSpdxData.Relationships = append(sbom.filteredSpdxData.Relationships, sbom.spdxData.Relationships[i])
		}
	}

	return nil
}

func (sbom *SBOMData) GetFilterSBOMInBytes() ([]byte, error) {
	return json.Marshal(sbom.filteredSpdxData)
}

func (sbom *SBOMData) IsNewRelevantSBOMDataExist() bool {
	return sbom.newRelevantData
}
