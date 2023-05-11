package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sniffer/pkg/context"
	"sniffer/pkg/utils"
	"strings"
	"sync"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// CreatorType should be one of "Person", "Organization", or "Tool"
	Organization                = "Organization"
	Tool                        = "Tool"
	Person                      = "Person"
	KubescapeOrganizationName   = "Kubescape"
	KubescapeNodeAgentName      = "KubescapeNodeAgent"
	RelationshipContainType     = "CONTAINS"
	directorySBOM               = "SBOM"
	sourceInfoDotnet            = "acquired package info from dotnet project assets file"
	sourceInfoNodeModule        = "acquired package info from installed node module manifest file"
	sourceInfoPythonPackage     = "acquired package info from installed python package manifest file"
	sourceInfoJava              = "acquired package info from installed java archive"
	sourceInfoGemFile           = "acquired package info from installed gem metadata file"
	sourceInfoGoModule          = "acquired package info from go module information"
	sourceInfoRustCargo         = "acquired package info from rust cargo manifest"
	sourceInfoPHPComposer       = "acquired package info from PHP composer manifest"
	sourceInfoCabal             = "acquired package info from cabal or stack manifest files"
	sourceInfoRebar             = "acquired package info from rebar3 or mix manifest file"
	sourceInfoLinuxKernel       = "acquired package info from linux kernel archive"
	sourceInfoLinuxKernelModule = "acquired package info from linux kernel module files"
	sourceInfoDefault           = "acquired package info from the following paths"
)

var (
	SBOMIncomplete = errors.New("SBOM Incomplete")
)

var spdxDataDirPath string
var sourceInfoRequiredPrefix []string

type SBOMData struct {
	spdxDataPath                             string
	filteredSpdxData                         spdxv1beta1.SBOMSPDXv2p3Filtered
	relevantRealtimeFilesBySPDXIdentifier    sync.Map
	relevantRealtimeFilesByPackageSourceInfo sync.Map
	newRelevantData                          bool
	alreadyExistSBOM                         bool
	status                                   string
	instanceID                               instanceidhandler.IInstanceID
}

type packageSourceInfoData struct {
	exist                 bool
	packageSPDXIdentifier []spdxv1beta1.ElementID
}

func createSBOMDir() {
	wd, err := os.Getwd()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("failed to get working directory", helpers.Error(err))
	}
	spdxDataDirPath = fmt.Sprintf("%s/%s", wd, directorySBOM)
	err = os.MkdirAll(spdxDataDirPath, os.ModeDir|os.ModePerm)
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("failed to create directory for SBOM resources", helpers.String("directory path", spdxDataDirPath), helpers.Error(err))
	}
}

func init() {
	createSBOMDir()
	sourceInfoPrefixData := []string{sourceInfoDotnet, sourceInfoNodeModule, sourceInfoPythonPackage, sourceInfoJava, sourceInfoGemFile, sourceInfoGoModule, sourceInfoRustCargo, sourceInfoPHPComposer, sourceInfoCabal, sourceInfoRebar, sourceInfoLinuxKernel, sourceInfoLinuxKernelModule, sourceInfoDefault}
	sourceInfoRequiredPrefix = append(sourceInfoRequiredPrefix, sourceInfoPrefixData...)
}

func CreateSBOMDataSPDXVersionV040(instanceID instanceidhandler.IInstanceID) SBOMFormat {

	return &SBOMData{
		spdxDataPath:                             fmt.Sprintf("%s/%s", spdxDataDirPath, instanceID.GetHashed()),
		filteredSpdxData:                         spdxv1beta1.SBOMSPDXv2p3Filtered{},
		relevantRealtimeFilesBySPDXIdentifier:    sync.Map{},
		relevantRealtimeFilesByPackageSourceInfo: sync.Map{},
		newRelevantData:                          false,
		alreadyExistSBOM:                         false,
		instanceID:                               instanceID,
		status:                                   "",
	}
}

func (sbom *SBOMData) saveSBOM(spdxData *spdxv1beta1.SBOMSPDXv2p3) error {
	f, err := os.Create(sbom.spdxDataPath)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	data, err := json.Marshal(spdxData)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func parsedFilesBySourceInfo(packageSourceInfo string) []string {
	needToMonitor := false
	for i := range sourceInfoRequiredPrefix {
		if strings.Contains(packageSourceInfo, sourceInfoRequiredPrefix[i]) {
			needToMonitor = true
			break
		}
	}
	if needToMonitor {
		fileListInString := utils.After(packageSourceInfo, ": ")
		return strings.Split(fileListInString, ", ")
	}
	return []string{}
}

func (sbom *SBOMData) StoreSBOM(sbomData any) error {
	spdxData, ok := sbomData.(*spdxv1beta1.SBOMSPDXv2p3)
	if !ok {
		return fmt.Errorf("storage format: StoreSBOM: SBOM data format is not supported")
	}

	err := sbom.saveSBOM(spdxData)
	if err != nil {
		return err
	}

	for i := range spdxData.Spec.SPDX.Files {
		sbom.relevantRealtimeFilesBySPDXIdentifier.Store(spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier, false)
	}
	for i := range spdxData.Spec.SPDX.Packages {
		filesBySourceInfo := parsedFilesBySourceInfo(spdxData.Spec.SPDX.Packages[i].PackageSourceInfo)
		for j := range filesBySourceInfo {
			if data, _ := sbom.relevantRealtimeFilesByPackageSourceInfo.Load(filesBySourceInfo[j]); data != nil {
				packageData := data.(*packageSourceInfoData)
				packageData.packageSPDXIdentifier = append(packageData.packageSPDXIdentifier, spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier)
			} else {
				sbom.relevantRealtimeFilesByPackageSourceInfo.Store(filesBySourceInfo[j], &packageSourceInfoData{exist: false, packageSPDXIdentifier: []spdxv1beta1.ElementID{spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier}})
			}
		}
	}

	sbom.filteredSpdxData.Spec = spdxData.Spec
	sbom.filteredSpdxData.Status = spdxData.Status
	sbom.filteredSpdxData.Spec.SPDX.CreationInfo.Creators = append(sbom.filteredSpdxData.Spec.SPDX.CreationInfo.Creators, []spdxv1beta1.Creator{
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

func (sbom *SBOMData) getSBOMDataSPDXFormat() (*spdxv1beta1.SBOMSPDXv2p3, error) {
	file, err := os.Open(sbom.spdxDataPath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	spdxData := spdxv1beta1.SBOMSPDXv2p3{}
	err = json.Unmarshal(bytes, &spdxData)
	if err != nil {
		return nil, err
	}

	return &spdxData, nil
}

func (sbom *SBOMData) FilterSBOM(sbomFileRelevantMap map[string]bool) error {
	if sbom.status == instanceidhandlerV1.Incomplete {
		return nil
	}
	sbom.newRelevantData = false

	spdxData, err := sbom.getSBOMDataSPDXFormat()
	if err != nil {
		return err
	}

	//filter relevant file list
	for i := range spdxData.Spec.SPDX.Files {
		if exist := sbomFileRelevantMap[spdxData.Spec.SPDX.Files[i].FileName]; exist {
			if data, _ := sbom.relevantRealtimeFilesBySPDXIdentifier.Load(spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier); data != nil && !data.(bool) {
				sbom.filteredSpdxData.Spec.SPDX.Files = append(sbom.filteredSpdxData.Spec.SPDX.Files, spdxData.Spec.SPDX.Files[i])
				sbom.relevantRealtimeFilesBySPDXIdentifier.Store(spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier, true)
				sbom.newRelevantData = true
			}
		}
	}

	//filter relevant file list from package source Info
	relevantPackageFromSourceInfoMap := make(map[spdxv1beta1.ElementID]bool)
	for realtimeFileName := range sbomFileRelevantMap {
		if data, _ := sbom.relevantRealtimeFilesByPackageSourceInfo.Load(realtimeFileName); data != nil && !data.(*packageSourceInfoData).exist {
			packageData := data.(*packageSourceInfoData)
			packageData.exist = true
			for i := range packageData.packageSPDXIdentifier {
				relevantPackageFromSourceInfoMap[packageData.packageSPDXIdentifier[i]] = true
			}
			sbom.newRelevantData = true
		}
	}

	//filter relationship list
	for i := range spdxData.Spec.SPDX.Relationships {
		switch spdxData.Spec.SPDX.Relationships[i].Relationship {
		case RelationshipContainType:
			if data, _ := sbom.relevantRealtimeFilesBySPDXIdentifier.Load(spdxData.Spec.SPDX.Relationships[i].RefB.ElementRefID); data != nil && data.(bool) {
				sbom.filteredSpdxData.Spec.SPDX.Relationships = append(sbom.filteredSpdxData.Spec.SPDX.Relationships, spdxData.Spec.SPDX.Relationships[i])
			}
			if exist := relevantPackageFromSourceInfoMap[spdxData.Spec.SPDX.Relationships[i].RefA.ElementRefID]; exist {
				sbom.filteredSpdxData.Spec.SPDX.Relationships = append(sbom.filteredSpdxData.Spec.SPDX.Relationships, spdxData.Spec.SPDX.Relationships[i])
			}
		default:
			sbom.filteredSpdxData.Spec.SPDX.Relationships = append(sbom.filteredSpdxData.Spec.SPDX.Relationships, spdxData.Spec.SPDX.Relationships[i])
		}
	}

	//filter relevant package list
	for i := range spdxData.Spec.SPDX.Packages {
		relevantPackageMap := make(map[spdxv1beta1.DocElementID]bool)
		for j := range sbom.filteredSpdxData.Spec.SPDX.Relationships {
			switch sbom.filteredSpdxData.Spec.SPDX.Relationships[j].Relationship {
			case RelationshipContainType:
				if alreadyExist := relevantPackageMap[sbom.filteredSpdxData.Spec.SPDX.Relationships[j].RefA]; !alreadyExist {
					if sbom.filteredSpdxData.Spec.SPDX.Relationships[j].RefA.ElementRefID == spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier {
						sbom.filteredSpdxData.Spec.SPDX.Packages = append(sbom.filteredSpdxData.Spec.SPDX.Packages, spdxData.Spec.SPDX.Packages[i])
					}
				}
			}
		}
		if exist := relevantPackageFromSourceInfoMap[spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier]; exist {
			sbom.filteredSpdxData.Spec.SPDX.Packages = append(sbom.filteredSpdxData.Spec.SPDX.Packages, spdxData.Spec.SPDX.Packages[i])
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

func (sbom *SBOMData) storeLabels(wlidData string, instanceID instanceidhandler.IInstanceID) {
	labels := instanceID.GetLabels()
	for i := range labels {
		if labels[i] == "" {
			delete(labels, i)
		} else {
			if i == instanceidhandlerV1.KindMetadataKey {
				labels[i] = wlid.GetKindFromWlid(wlidData)
			} else if i == instanceidhandlerV1.NameMetadataKey {
				labels[i] = wlid.GetNameFromWlid(wlidData)
			}
			errs := validation.IsValidLabelValue(labels[i])
			if len(errs) != 0 {
				logger.L().Debug("label is not valid", helpers.String("label", labels[i]))
				for j := range errs {
					logger.L().Debug("label err description", helpers.String("Err: ", errs[j]))
				}
				delete(labels, i)
			}
		}
	}
	sbom.filteredSpdxData.ObjectMeta.SetLabels(labels)
}

func (sbom *SBOMData) storeAnnotations(wlidData, imageID string, instanceID instanceidhandler.IInstanceID) {
	annotations := make(map[string]string)
	annotations[instanceidhandlerV1.WlidMetadataKey] = wlidData
	annotations[instanceidhandlerV1.InstanceIDMetadataKey] = instanceID.GetStringFormatted()
	annotations[instanceidhandlerV1.ContainerNameMetadataKey] = instanceID.GetContainerName()
	annotations[instanceidhandlerV1.ImageIDMetadataKey] = imageID
	annotations[instanceidhandlerV1.StatusMetadataKey] = sbom.status

	sbom.filteredSpdxData.ObjectMeta.SetAnnotations(annotations)
}

func (sbom *SBOMData) StoreMetadata(wlidData string, imageID string, instanceID instanceidhandler.IInstanceID) {
	sbom.storeLabels(wlidData, instanceID)
	sbom.storeAnnotations(wlidData, imageID, instanceID)
}

func (sc *SBOMData) CleanResources() {
	err := os.Remove(sc.spdxDataPath)
	if err != nil {
		logger.L().Debug("fail to remove file", helpers.String("file name", sc.spdxDataPath), helpers.Error(err))
	}
}

func (sc *SBOMData) ValidateSBOM() error {
	sbom, err := sc.getSBOMDataSPDXFormat()
	if err != nil {
		logger.L().Debug("fail to validate SBOM", helpers.String("file name", sc.spdxDataPath), helpers.Error(err))
		return nil
	}
	annotationes := sbom.GetAnnotations()
	if val, ok := annotationes[instanceidhandlerV1.StatusMetadataKey]; ok {
		if val == instanceidhandlerV1.Incomplete {
			sc.status = instanceidhandlerV1.Incomplete
			return SBOMIncomplete
		}
	}
	return nil
}
