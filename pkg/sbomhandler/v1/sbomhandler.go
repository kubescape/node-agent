package sbomhandler

import (
	"errors"
	"node-agent/pkg/sbomhandler"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	// CreatorType should be one of "Person", "Organization", or "Tool"
	Organization = "Organization"
	Tool         = "Tool"

	KubescapeOrganizationName   = "Kubescape"
	KubescapeNodeAgentName      = "KubescapeNodeAgent"
	RelationshipContainType     = "CONTAINS"
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
	sourceInfoRequiredPrefix = []string{sourceInfoDotnet, sourceInfoNodeModule, sourceInfoPythonPackage, sourceInfoJava, sourceInfoGemFile, sourceInfoGoModule, sourceInfoRustCargo, sourceInfoPHPComposer, sourceInfoCabal, sourceInfoRebar, sourceInfoLinuxKernel, sourceInfoLinuxKernelModule, sourceInfoDefault}
)

type SBOMHandler struct {
	storageClient storage.StorageClient
}

var _ sbomhandler.SBOMHandlerClient = (*SBOMHandler)(nil)

func CreateSBOMHandler(sc storage.StorageClient) *SBOMHandler {
	return &SBOMHandler{
		storageClient: sc,
	}
}

func (sc *SBOMHandler) FilterSBOM(watchedContainer *utils.WatchedContainerData, sbomFileRelevantMap map[string]bool) error {
	newRelevantData := false

	if watchedContainer.FilteredSpdxData == nil {
		if watchedContainer.InstanceID == nil {
			return errors.New("instance id is nil")
		}
		filterSBOMKey, err := watchedContainer.InstanceID.GetSlug()
		if err != nil {
			return err
		}
		watchedContainer.FilteredSpdxData = &v1beta1.SBOMSPDXv2p3Filtered{
			ObjectMeta: metav1.ObjectMeta{
				Name: filterSBOMKey,
				Annotations: map[string]string{
					instanceidhandler.WlidMetadataKey:          watchedContainer.Wlid,
					instanceidhandler.InstanceIDMetadataKey:    watchedContainer.InstanceID.GetStringFormatted(),
					instanceidhandler.ContainerNameMetadataKey: watchedContainer.InstanceID.GetContainerName(),
					instanceidhandler.ImageIDMetadataKey:       watchedContainer.ImageID,
					instanceidhandler.StatusMetadataKey:        "",
				},
				Labels: utils.GetLabels(watchedContainer, false),
			},
		}
	}

	SBOMKey, err := names.ImageInfoToSlug(watchedContainer.ImageTag, watchedContainer.ImageID)
	if err != nil {
		return err
	}
	spdxData, err := sc.storageClient.GetSBOM(SBOMKey)
	if err != nil {
		return err
	}

	// check SBOM is complete
	if status, ok := spdxData.Annotations[instanceidhandler.StatusMetadataKey]; ok {
		watchedContainer.FilteredSpdxData.Annotations[instanceidhandler.StatusMetadataKey] = status
		if status == instanceidhandler.Incomplete {
			// stop processing after storing filtered SBOM
			watchedContainer.SyncChannel <- utils.IncompleteSBOMError
		}
	}

	// parse SBOM if resource version is higher than the one in memory
	if spdxData != nil && utils.Atoi(spdxData.ResourceVersion) > watchedContainer.SBOMResourceVersion {
		logger.L().Debug("SBOM resource version is higher than the one in memory, parsing SBOM", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
		// fill relevantRealtimeFilesByPackageSourceInfo and relevantRealtimeFilesBySPDXIdentifier
		for i := range spdxData.Spec.SPDX.Files {
			watchedContainer.RelevantRealtimeFilesBySPDXIdentifier[spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier] = false
		}
		for i := range spdxData.Spec.SPDX.Packages {
			filesBySourceInfo := parsedFilesBySourceInfo(spdxData.Spec.SPDX.Packages[i].PackageSourceInfo)
			for j := range filesBySourceInfo {
				if packageData, ok := watchedContainer.RelevantRealtimeFilesByPackageSourceInfo[filesBySourceInfo[j]]; ok {
					packageData.PackageSPDXIdentifier = append(packageData.PackageSPDXIdentifier, spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier)
				} else {
					watchedContainer.RelevantRealtimeFilesByPackageSourceInfo[filesBySourceInfo[j]] = &utils.PackageSourceInfoData{Exist: false, PackageSPDXIdentifier: []v1beta1.ElementID{spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier}}
				}
			}
		}
		// save files, packages and relationships
		files := watchedContainer.FilteredSpdxData.Spec.SPDX.Files
		packages := watchedContainer.FilteredSpdxData.Spec.SPDX.Packages
		relationships := watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships
		// copy spec and status
		watchedContainer.FilteredSpdxData.Spec = spdxData.Spec
		watchedContainer.FilteredSpdxData.Status = spdxData.Status
		// restore files, packages and relationships
		watchedContainer.FilteredSpdxData.Spec.SPDX.Files = files
		watchedContainer.FilteredSpdxData.Spec.SPDX.Packages = packages
		watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships = relationships
		// rewrite creation info
		if watchedContainer.FilteredSpdxData.Spec.SPDX.CreationInfo != nil {
			watchedContainer.FilteredSpdxData.Spec.SPDX.CreationInfo.Creators = append(watchedContainer.FilteredSpdxData.Spec.SPDX.CreationInfo.Creators, []v1beta1.Creator{
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
		// update resource version
		watchedContainer.SBOMResourceVersion = utils.Atoi(spdxData.ResourceVersion)
		newRelevantData = true
	}

	// filter relevant file list
	for i := range spdxData.Spec.SPDX.Files {
		if sbomFileRelevantMap[spdxData.Spec.SPDX.Files[i].FileName] {
			if !watchedContainer.RelevantRealtimeFilesBySPDXIdentifier[spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier] {
				watchedContainer.FilteredSpdxData.Spec.SPDX.Files = append(watchedContainer.FilteredSpdxData.Spec.SPDX.Files, spdxData.Spec.SPDX.Files[i])
				watchedContainer.RelevantRealtimeFilesBySPDXIdentifier[spdxData.Spec.SPDX.Files[i].FileSPDXIdentifier] = true
				newRelevantData = true
			}
		}
	}

	// filter relevant file list from package source Info
	relevantPackageFromSourceInfoMap := make(map[v1beta1.ElementID]bool)
	for realtimeFileName := range sbomFileRelevantMap {
		if packageData := watchedContainer.RelevantRealtimeFilesByPackageSourceInfo[realtimeFileName]; packageData != nil && !packageData.Exist {
			packageData.Exist = true
			for i := range packageData.PackageSPDXIdentifier {
				relevantPackageFromSourceInfoMap[packageData.PackageSPDXIdentifier[i]] = true
			}
			newRelevantData = true
		}
	}

	if newRelevantData {
		// filter relationship list
		relationships := sets.New[*v1beta1.Relationship](watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships...)
		for i := range spdxData.Spec.SPDX.Relationships {
			switch spdxData.Spec.SPDX.Relationships[i].Relationship {
			case RelationshipContainType:
				if watchedContainer.RelevantRealtimeFilesBySPDXIdentifier[spdxData.Spec.SPDX.Relationships[i].RefB.ElementRefID] {
					relationships.Insert(spdxData.Spec.SPDX.Relationships[i])
				}
				if relevantPackageFromSourceInfoMap[spdxData.Spec.SPDX.Relationships[i].RefA.ElementRefID] {
					relationships.Insert(spdxData.Spec.SPDX.Relationships[i])
				}
			default:
				relationships.Insert(spdxData.Spec.SPDX.Relationships[i])
			}
		}
		watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships = relationships.UnsortedList()

		// filter relevant package list
		packages := sets.New[*v1beta1.Package](watchedContainer.FilteredSpdxData.Spec.SPDX.Packages...)
		for i := range spdxData.Spec.SPDX.Packages {
			for j := range watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships {
				switch watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships[j].Relationship {
				case RelationshipContainType:
					if watchedContainer.FilteredSpdxData.Spec.SPDX.Relationships[j].RefA.ElementRefID == spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier {
						packages.Insert(spdxData.Spec.SPDX.Packages[i])
					}
				}
			}
			if exist := relevantPackageFromSourceInfoMap[spdxData.Spec.SPDX.Packages[i].PackageSPDXIdentifier]; exist {
				packages.Insert(spdxData.Spec.SPDX.Packages[i])
			}
		}
		watchedContainer.FilteredSpdxData.Spec.SPDX.Packages = packages.UnsortedList()

		// store new filtered SBOM
		err = sc.storageClient.CreateFilteredSBOM(watchedContainer.FilteredSpdxData)
		if err != nil {
			return err
		}
		logger.L().Info("filtered SBOM has been stored successfully", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	return nil
}

func (sc *SBOMHandler) IncrementImageUse(imageID string) {
	sc.storageClient.IncrementImageUse(imageID)
}

func (sc *SBOMHandler) DecrementImageUse(imageID string) {
	sc.storageClient.DecrementImageUse(imageID)
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
