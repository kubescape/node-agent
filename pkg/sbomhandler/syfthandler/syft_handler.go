package syfthandler

import (
	"fmt"
	"node-agent/pkg/sbomhandler"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SyftHandler struct {
	storageClient storage.StorageClient
}

var _ sbomhandler.SBOMHandlerClient = (*SyftHandler)(nil)

func CreateSyftSBOMHandler(sc storage.StorageClient) *SyftHandler {
	return &SyftHandler{
		storageClient: sc,
	}
}

func (sc *SyftHandler) FilterSBOM(watchedContainer *utils.WatchedContainerData, sbomFileRelevantMap map[string]bool) error {

	if watchedContainer.InstanceID == nil {
		return fmt.Errorf("instance id is nil")
	}

	filteredSBOMKey, err := watchedContainer.InstanceID.GetSlug()
	if err != nil {
		return err
	}

	filteredSyftSBOM := v1beta1.SBOMSyftFiltered{
		ObjectMeta: metav1.ObjectMeta{
			Name: filteredSBOMKey,
			Annotations: map[string]string{
				instanceidhandler.WlidMetadataKey:          watchedContainer.Wlid,
				instanceidhandler.InstanceIDMetadataKey:    watchedContainer.InstanceID.GetStringFormatted(),
				instanceidhandler.ContainerNameMetadataKey: watchedContainer.InstanceID.GetContainerName(),
				instanceidhandler.ImageIDMetadataKey:       watchedContainer.ImageID,
			},
			Labels: utils.GetLabels(watchedContainer, false),
		},
	}

	// retrieve SBOM from storage
	SBOMKey, err := names.ImageInfoToSlug(watchedContainer.ImageTag, watchedContainer.ImageID)
	if err != nil {
		return err
	}

	syftData, err := sc.storageClient.GetSBOM(SBOMKey)
	if err != nil {
		return err
	}

	// check SBOM is complete
	if status, ok := syftData.Annotations[instanceidhandler.StatusMetadataKey]; ok {
		if status == instanceidhandler.Incomplete {
			watchedContainer.SyncChannel <- utils.IncompleteSBOMError
		}
	}

	newRelevantData := false

	// if resource version is higher than in-memory, delete saved relevancy info
	if syftData != nil && utils.Atoi(syftData.ResourceVersion) > watchedContainer.SBOMResourceVersion {
		logger.L().Debug("SBOM resource version is higher than the one in memory, parsing SBOM", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))

		for _, file := range syftData.Spec.Syft.Files {
			watchedContainer.RelevantSyftFilesByIdentifier[file.ID] = false
		}

		watchedContainer.SBOMResourceVersion = utils.Atoi(syftData.ResourceVersion)
	}

	// check if there are new relevant files
	for _, file := range syftData.Spec.Syft.Files {
		if sbomFileRelevantMap[file.Location.RealPath] && !watchedContainer.RelevantSyftFilesByIdentifier[file.ID] {
			newRelevantData = true
			break
		}
	}

	if !newRelevantData {
		return nil
	}

	filteredSyftDoc := filterRelevantFilesInSBOM(syftData.Spec.Syft, sbomFileRelevantMap)

	// update relevant files internally
	watchedContainer.RelevantSyftFilesByIdentifier = make(map[string]bool, 0)
	for _, file := range filteredSyftDoc.Files {
		watchedContainer.RelevantSyftFilesByIdentifier[file.ID] = true
	}

	filteredSyftSBOM.Spec.Syft = filteredSyftDoc

	if err = sc.storageClient.CreateFilteredSBOM(&filteredSyftSBOM); err != nil {
		return err
	}
	logger.L().Info("filtered SBOM has been stored successfully", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))

	return nil
}

func filterRelevantFilesInSBOM(syftDoc v1beta1.SyftDocument, sbomFileRelevantMap map[string]bool) v1beta1.SyftDocument {
	relevantSBOM := v1beta1.SyftDocument{
		Secrets:        syftDoc.Secrets,
		SyftSource:     syftDoc.SyftSource,
		Distro:         syftDoc.Distro,
		SyftDescriptor: syftDoc.SyftDescriptor,
		Schema:         syftDoc.Schema,
	}

	// build map of relevant file IDs
	relevantFileIdentifiers := make(map[string]bool, 0)
	relevantFiles := make([]v1beta1.SyftFile, 0)
	for _, file := range syftDoc.Files {
		if sbomFileRelevantMap[file.Location.RealPath] {
			relevantFileIdentifiers[file.ID] = true
			relevantFiles = append(relevantFiles, file)
		}
	}

	// filter relevant relationships. A relationship is relevant if the child is a relevant file or artifact
	relevantRelationshipsArtifactsByIdentifier := make(map[string]bool, 0)
	relevantRelationships := make([]v1beta1.SyftRelationship, 0)
	for _, relationship := range syftDoc.ArtifactRelationships {
		if _, ok := relevantFileIdentifiers[relationship.Child]; ok {
			relevantRelationshipsArtifactsByIdentifier[relationship.Parent] = true

			relevantRelationships = append(relevantRelationships, relationship)
		}
	}

	// loop again so we can add the artifacts relationships where the child is an relevant artifact
	for _, relationship := range syftDoc.ArtifactRelationships {
		if _, ok := relevantFileIdentifiers[relationship.Child]; ok {
			if _, ok := relevantRelationshipsArtifactsByIdentifier[relationship.Parent]; ok {
				continue
			}
			relevantRelationshipsArtifactsByIdentifier[relationship.Parent] = true

			relevantRelationships = append(relevantRelationships, relationship)
		}
	}

	relevantArtifacts := make([]v1beta1.SyftPackage, 0)
	// filter relevant artifacts. An artifact is relevant if it is in the relevant relationships
	for _, artifact := range syftDoc.Artifacts {
		if _, ok := relevantRelationshipsArtifactsByIdentifier[artifact.ID]; ok {
			relevantArtifacts = append(relevantArtifacts, artifact)
		}
	}

	relevantSBOM.Files = relevantFiles
	relevantSBOM.Artifacts = relevantArtifacts
	relevantSBOM.ArtifactRelationships = relevantRelationships

	return relevantSBOM
}

func (sc *SyftHandler) IncrementImageUse(imageID string) {

}
func (sc *SyftHandler) DecrementImageUse(imageID string) {

}
