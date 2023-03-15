package sbom

import (
	"fmt"
	"sync"

	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// CreatorType should be one of "Person", "Organization", or "Tool"
	Organization              = "Organization"
	Tool                      = "Tool"
	Person                    = "Person"
	KubescapeOrganizationName = "Kubescape"
	KubescapeNodeAgentName    = "KubescapeNodeAgent"
	RelationshipContainType   = "CONTAINS"
	SPDXRefpre                = "SPDXRef-"
)

type SBOMData struct {
	spdxData                              spdxv1beta1.SBOMSPDXv2p3
	filteredSpdxData                      spdxv1beta1.SBOMSPDXv2p3
	relevantRealtimeFilesBySPDXIdentifier sync.Map
	newRelevantData                       bool
	alreadyExistSBOM                      bool
}

func CreateSBOMDataSPDXVersionV040() *SBOMData {
	return &SBOMData{
		filteredSpdxData:                      spdxv1beta1.SBOMSPDXv2p3{},
		relevantRealtimeFilesBySPDXIdentifier: sync.Map{},
		newRelevantData:                       false,
		alreadyExistSBOM:                      false,
	}
}

func (sbom *SBOMData) StoreSBOM(sbomData any) error {
	spdxData, ok := sbomData.(*spdxv1beta1.SBOMSPDXv2p3)
	if !ok {
		return fmt.Errorf("storage format: StoreSBOM: SBOM data format is not supported")
	}

	sbom.spdxData = *spdxData
	for i := range sbom.spdxData.Spec.SPDX.Files {
		sbom.relevantRealtimeFilesBySPDXIdentifier.Store(spdxv1beta1.ElementID(sbom.spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier), false)
	}
	sbom.filteredSpdxData = sbom.spdxData
	sbom.spdxData.Spec.SPDX.CreationInfo.Creators = append(sbom.spdxData.Spec.SPDX.CreationInfo.Creators, []spdxv1beta1.Creator{
		{
			CreatorType: Organization,
			Creator:     KubescapeOrganizationName,
		},
		{
			CreatorType: Tool,
			Creator:     KubescapeNodeAgentName,
		},
	}...)

	sbom.filteredSpdxData.ObjectMeta = metav1.ObjectMeta{}
	sbom.filteredSpdxData.Spec.SPDX.Files = make([]*spdxv1beta1.File, 0)
	sbom.filteredSpdxData.Spec.SPDX.Packages = make([]*spdxv1beta1.Package, 0)
	sbom.filteredSpdxData.Spec.SPDX.Relationships = make([]*spdxv1beta1.Relationship, 0)
	sbom.alreadyExistSBOM = true

	return nil
}

func (sbom *SBOMData) FilterSBOM(sbomFileRelevantMap map[string]bool) error {
	sbom.newRelevantData = false
	//filter relevant file list
	for i := range sbom.spdxData.Spec.SPDX.Files {
		if exist := sbomFileRelevantMap[sbom.spdxData.Spec.SPDX.Files[i].FileName]; exist {
			if data, _ := sbom.relevantRealtimeFilesBySPDXIdentifier.Load(spdxv1beta1.ElementID(sbom.spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier)); data != nil && !data.(bool) {
				sbom.filteredSpdxData.Spec.SPDX.Files = append(sbom.filteredSpdxData.Spec.SPDX.Files, sbom.spdxData.Spec.SPDX.Files[i])
				sbom.relevantRealtimeFilesBySPDXIdentifier.Store(spdxv1beta1.ElementID(sbom.spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier), true)
				sbom.newRelevantData = true
			}
		}
	}

	//filter relationship list
	for i := range sbom.spdxData.Spec.SPDX.Relationships {
		switch sbom.spdxData.Spec.SPDX.Relationships[i].Relationship {
		case RelationshipContainType:
			if data, _ := sbom.relevantRealtimeFilesBySPDXIdentifier.Load(spdxv1beta1.ElementID(sbom.spdxData.Spec.SPDX.Relationships[i].RefB.ElementRefID)); data != nil && data.(bool) {
				sbom.filteredSpdxData.Spec.SPDX.Relationships = append(sbom.filteredSpdxData.Spec.SPDX.Relationships, sbom.spdxData.Spec.SPDX.Relationships[i])
			}
		default:
			sbom.filteredSpdxData.Spec.SPDX.Relationships = append(sbom.filteredSpdxData.Spec.SPDX.Relationships, sbom.spdxData.Spec.SPDX.Relationships[i])
		}
	}

	//filter relevant package list
	for i := range sbom.spdxData.Spec.SPDX.Packages {
		relevantPackageMap := make(map[spdxv1beta1.DocElementID]bool)
		for j := range sbom.filteredSpdxData.Spec.SPDX.Relationships {
			switch sbom.filteredSpdxData.Spec.SPDX.Relationships[j].Relationship {
			case RelationshipContainType:
				if alreadyExist := relevantPackageMap[sbom.filteredSpdxData.Spec.SPDX.Relationships[j].RefA]; !alreadyExist {
					if spdxv1beta1.ElementID(sbom.filteredSpdxData.Spec.SPDX.Relationships[j].RefA.ElementRefID) == sbom.spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier {
						sbom.filteredSpdxData.Spec.SPDX.Packages = append(sbom.filteredSpdxData.Spec.SPDX.Packages, sbom.spdxData.Spec.SPDX.Packages[i])
					}
				}
			}
		}
	}

	return nil
}

func (sbom *SBOMData) GetFilterSBOMData() any {
	return &sbom.filteredSpdxData
}

func (sbom *SBOMData) IsNewRelevantSBOMDataExist() bool {
	return sbom.newRelevantData
}

func (sbom *SBOMData) IsSBOMAlreadyExist() bool {
	return sbom.alreadyExistSBOM
}

func (sbom *SBOMData) StoreFilteredSBOMName(name string) {
	sbom.filteredSpdxData.ObjectMeta.SetName(name)
}
