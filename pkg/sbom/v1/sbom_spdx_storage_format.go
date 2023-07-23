package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"node-agent/pkg/utils"
	"strings"
	"sync"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spf13/afero"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// CreatorType should be one of "Person", "Organization", or "Tool"
	Organization = "Organization"
	Tool         = "Tool"

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
	sbomFs                                   afero.Fs
	spdxDataPath                             string
	filteredSpdxData                         spdxv1beta1.SBOMSPDXv2p3Filtered
	relevantRealtimeFilesBySPDXIdentifier    sync.Map
	relevantRealtimeFilesByPackageSourceInfo sync.Map
	newRelevantData                          bool
	alreadyExistSBOM                         bool
	status                                   string
	instanceID                               instanceidhandler.IInstanceID
}

var _ SBOMFormat = (*SBOMData)(nil)

type packageSourceInfoData struct {
	exist                 bool
	packageSPDXIdentifier []spdxv1beta1.ElementID
}

func init() {
	sourceInfoPrefixData := []string{sourceInfoDotnet, sourceInfoNodeModule, sourceInfoPythonPackage, sourceInfoJava, sourceInfoGemFile, sourceInfoGoModule, sourceInfoRustCargo, sourceInfoPHPComposer, sourceInfoCabal, sourceInfoRebar, sourceInfoLinuxKernel, sourceInfoLinuxKernelModule, sourceInfoDefault}
	sourceInfoRequiredPrefix = append(sourceInfoRequiredPrefix, sourceInfoPrefixData...)
}

func CreateSBOMDataSPDXVersionV040(instanceID instanceidhandler.IInstanceID, sbomFs afero.Fs) SBOMFormat {
	spdxDataDirPath = "/data/" + directorySBOM
	_ = sbomFs.Mkdir(spdxDataDirPath, 0755)
	return &SBOMData{
		sbomFs:                                   sbomFs,
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

func (sc *SBOMData) saveSBOM(ctx context.Context, spdxData *spdxv1beta1.SBOMSPDXv2p3) error {
	// _, span := otel.Tracer("").Start(ctx, "SBOMData.saveSBOM")
	// defer span.End()
	logger.L().Debug("saving SBOM", helpers.String("path", sc.spdxDataPath))

	data, err := json.Marshal(spdxData)
	if err != nil {
		return err
	}
	err = afero.WriteFile(sc.sbomFs, sc.spdxDataPath, data, 0644)
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

func (sc *SBOMData) StoreSBOM(ctx context.Context, sbomData any) error {
	// ctx, span := otel.Tracer("").Start(ctx, "SBOMData.StoreSBOM")
	// defer span.End()
	spdxData, ok := sbomData.(*spdxv1beta1.SBOMSPDXv2p3)
	if !ok {
		return fmt.Errorf("storage format: StoreSBOM: SBOM data format is not supported")
	}

	err := sc.saveSBOM(ctx, spdxData)
	if err != nil {
		return err
	}

	for i := range spdxData.Spec.SPDX.Files {
		sc.relevantRealtimeFilesBySPDXIdentifier.Store(spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier, false)
	}
	for i := range spdxData.Spec.SPDX.Packages {
		filesBySourceInfo := parsedFilesBySourceInfo(spdxData.Spec.SPDX.Packages[i].PackageSourceInfo)
		for j := range filesBySourceInfo {
			if data, _ := sc.relevantRealtimeFilesByPackageSourceInfo.Load(filesBySourceInfo[j]); data != nil {
				packageData := data.(*packageSourceInfoData)
				packageData.packageSPDXIdentifier = append(packageData.packageSPDXIdentifier, spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier)
			} else {
				sc.relevantRealtimeFilesByPackageSourceInfo.Store(filesBySourceInfo[j], &packageSourceInfoData{exist: false, packageSPDXIdentifier: []spdxv1beta1.ElementID{spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier}})
			}
		}
	}

	sc.filteredSpdxData.Spec = spdxData.Spec
	sc.filteredSpdxData.Status = spdxData.Status
	if sc.filteredSpdxData.Spec.SPDX.CreationInfo != nil {
		sc.filteredSpdxData.Spec.SPDX.CreationInfo.Creators = append(sc.filteredSpdxData.Spec.SPDX.CreationInfo.Creators, []spdxv1beta1.Creator{
			{
				CreatorType: Organization,
				Creator:     KubescapeOrganizationName,
			},
			{
				CreatorType: Tool,
				Creator:     KubescapeNodeAgentName,
			},
		}...)
	}

	sc.filteredSpdxData.ObjectMeta = metav1.ObjectMeta{}
	sc.filteredSpdxData.Spec.SPDX.Files = make([]*spdxv1beta1.File, 0)
	sc.filteredSpdxData.Spec.SPDX.Packages = make([]*spdxv1beta1.Package, 0)
	sc.filteredSpdxData.Spec.SPDX.Relationships = make([]*spdxv1beta1.Relationship, 0)
	sc.alreadyExistSBOM = true

	return nil
}

func (sc *SBOMData) getSBOMDataSPDXFormat(ctx context.Context) (*spdxv1beta1.SBOMSPDXv2p3, error) {
	// _, span := otel.Tracer("").Start(ctx, "SBOMData.getSBOMDataSPDXFormat")
	// defer span.End()

	bytes, err := afero.ReadFile(sc.sbomFs, sc.spdxDataPath)
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

func (sc *SBOMData) FilterSBOM(ctx context.Context, sbomFileRelevantMap map[string]bool) error {
	// ctx, span := otel.Tracer("").Start(ctx, "SBOMData.FilterSBOM")
	// defer span.End()

	if sc.status == instanceidhandlerV1.Incomplete {
		return nil
	}
	sc.newRelevantData = false

	spdxData, err := sc.getSBOMDataSPDXFormat(ctx)
	if err != nil {
		return err
	}

	//filter relevant file list
	for i := range spdxData.Spec.SPDX.Files {
		if exist := sbomFileRelevantMap[spdxData.Spec.SPDX.Files[i].FileName]; exist {
			if data, _ := sc.relevantRealtimeFilesBySPDXIdentifier.Load(spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier); data != nil && !data.(bool) {
				sc.filteredSpdxData.Spec.SPDX.Files = append(sc.filteredSpdxData.Spec.SPDX.Files, spdxData.Spec.SPDX.Files[i])
				sc.relevantRealtimeFilesBySPDXIdentifier.Store(spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier, true)
				sc.newRelevantData = true
			}
		}
	}

	//filter relevant file list from package source Info
	relevantPackageFromSourceInfoMap := make(map[spdxv1beta1.ElementID]bool)
	for realtimeFileName := range sbomFileRelevantMap {
		if data, _ := sc.relevantRealtimeFilesByPackageSourceInfo.Load(realtimeFileName); data != nil && !data.(*packageSourceInfoData).exist {
			packageData := data.(*packageSourceInfoData)
			packageData.exist = true
			for i := range packageData.packageSPDXIdentifier {
				relevantPackageFromSourceInfoMap[packageData.packageSPDXIdentifier[i]] = true
			}
			sc.newRelevantData = true
		}
	}

	//filter relationship list
	for i := range spdxData.Spec.SPDX.Relationships {
		switch spdxData.Spec.SPDX.Relationships[i].Relationship {
		case RelationshipContainType:
			if data, _ := sc.relevantRealtimeFilesBySPDXIdentifier.Load(spdxData.Spec.SPDX.Relationships[i].RefB.ElementRefID); data != nil && data.(bool) {
				sc.filteredSpdxData.Spec.SPDX.Relationships = append(sc.filteredSpdxData.Spec.SPDX.Relationships, spdxData.Spec.SPDX.Relationships[i])
			}
			if exist := relevantPackageFromSourceInfoMap[spdxData.Spec.SPDX.Relationships[i].RefA.ElementRefID]; exist {
				sc.filteredSpdxData.Spec.SPDX.Relationships = append(sc.filteredSpdxData.Spec.SPDX.Relationships, spdxData.Spec.SPDX.Relationships[i])
			}
		default:
			sc.filteredSpdxData.Spec.SPDX.Relationships = append(sc.filteredSpdxData.Spec.SPDX.Relationships, spdxData.Spec.SPDX.Relationships[i])
		}
	}

	//filter relevant package list
	for i := range spdxData.Spec.SPDX.Packages {
		relevantPackageMap := make(map[spdxv1beta1.DocElementID]bool)
		for j := range sc.filteredSpdxData.Spec.SPDX.Relationships {
			switch sc.filteredSpdxData.Spec.SPDX.Relationships[j].Relationship {
			case RelationshipContainType:
				if alreadyExist := relevantPackageMap[sc.filteredSpdxData.Spec.SPDX.Relationships[j].RefA]; !alreadyExist {
					if sc.filteredSpdxData.Spec.SPDX.Relationships[j].RefA.ElementRefID == spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier {
						sc.filteredSpdxData.Spec.SPDX.Packages = append(sc.filteredSpdxData.Spec.SPDX.Packages, spdxData.Spec.SPDX.Packages[i])
					}
				}
			}
		}
		if exist := relevantPackageFromSourceInfoMap[spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier]; exist {
			sc.filteredSpdxData.Spec.SPDX.Packages = append(sc.filteredSpdxData.Spec.SPDX.Packages, spdxData.Spec.SPDX.Packages[i])
		}
	}

	return nil
}

func (sc *SBOMData) GetFilterSBOMData() any {
	return &sc.filteredSpdxData
}

func (sc *SBOMData) IsNewRelevantSBOMDataExist() bool {
	return sc.newRelevantData
}

func (sc *SBOMData) IsSBOMAlreadyExist() bool {
	return sc.alreadyExistSBOM
}

func (sc *SBOMData) SetFilteredSBOMName(name string) {
	sc.filteredSpdxData.ObjectMeta.SetName(name)
}

func (sc *SBOMData) storeLabels(wlidData string, instanceID instanceidhandler.IInstanceID) {
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
	sc.filteredSpdxData.ObjectMeta.SetLabels(labels)
}

func (sc *SBOMData) storeAnnotations(wlidData, imageID string, instanceID instanceidhandler.IInstanceID) {
	annotations := make(map[string]string)
	annotations[instanceidhandlerV1.WlidMetadataKey] = wlidData
	annotations[instanceidhandlerV1.InstanceIDMetadataKey] = instanceID.GetStringFormatted()
	annotations[instanceidhandlerV1.ContainerNameMetadataKey] = instanceID.GetContainerName()
	annotations[instanceidhandlerV1.ImageIDMetadataKey] = imageID
	annotations[instanceidhandlerV1.StatusMetadataKey] = sc.status

	sc.filteredSpdxData.ObjectMeta.SetAnnotations(annotations)
}

func (sc *SBOMData) StoreMetadata(ctx context.Context, wlidData, imageID string, instanceID instanceidhandler.IInstanceID) {
	// _, span := otel.Tracer("").Start(ctx, "SBOMData.StoreMetadata")
	// defer span.End()
	sc.storeLabels(wlidData, instanceID)
	sc.storeAnnotations(wlidData, imageID, instanceID)
}

func (sc *SBOMData) CleanResources() {
	err := sc.sbomFs.Remove(sc.spdxDataPath)
	if err != nil {
		logger.L().Debug("fail to remove file", helpers.String("file name", sc.spdxDataPath), helpers.Error(err))
	}
}

func (sc *SBOMData) ValidateSBOM(ctx context.Context) error {
	// ctx, span := otel.Tracer("").Start(ctx, "SBOMData.ValidateSBOM")
	// defer span.End()
	sbom, err := sc.getSBOMDataSPDXFormat(ctx)
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
