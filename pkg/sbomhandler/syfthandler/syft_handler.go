package syfthandler

import (
	"fmt"
	"node-agent/pkg/sbomhandler"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
		return nil
	}

	newRelevantData := false

	// retrieve SBOM from storage
	SBOMKey, err := names.ImageInfoToSlug(watchedContainer.ImageTag, watchedContainer.ImageID)
	if err != nil {
		return err
	}

	syftData, err := sc.storageClient.GetSBOM(SBOMKey)
	if err != nil {
		return fmt.Errorf("failed to get SBOM from storage: %w", err)
	}
	if syftData == nil {
		return nil
	}

	// check SBOM is complete
	if syftData.Annotations != nil {
		if status, ok := syftData.Annotations[helpersv1.StatusMetadataKey]; ok {
			if status == helpersv1.Incomplete {
				watchedContainer.SyncChannel <- utils.IncompleteSBOMError
			}
			// dwertent
			if status == helpersv1.Unauthorize {
				watchedContainer.SyncChannel <- utils.IncompleteSBOMError
			}
		}
	}

	if watchedContainer.SBOMSyftFiltered == nil {
		filteredSBOMKey, err := watchedContainer.InstanceID.GetSlug()
		if err != nil {
			return err
		}

		if filteredSBOM, err := sc.storageClient.GetFilteredSBOM(filteredSBOMKey); err != nil {
			logger.L().Debug("filtered SBOM not found, creating new one", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.String("filtered SBOM", filteredSBOMKey))
			watchedContainer.SBOMSyftFiltered = &v1beta1.SBOMSyftFiltered{
				ObjectMeta: metav1.ObjectMeta{
					Name: filteredSBOMKey,
					Annotations: map[string]string{
						helpersv1.WlidMetadataKey:          watchedContainer.Wlid,
						helpersv1.InstanceIDMetadataKey:    watchedContainer.InstanceID.GetStringFormatted(),
						helpersv1.ContainerNameMetadataKey: watchedContainer.InstanceID.GetContainerName(),
						helpersv1.ImageIDMetadataKey:       watchedContainer.ImageID,
						helpersv1.ImageTagMetadataKey:      watchedContainer.ImageTag,
						helpersv1.StatusMetadataKey:        helpersv1.Ready,
					},
					Labels: utils.GetLabels(watchedContainer, false),
				},
			}
		} else {
			logger.L().Debug("filtered SBOM found, using it", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.String("filtered SBOM", filteredSBOMKey))
			filteredSBOM.ObjectMeta.ResourceVersion = ""
			filteredSBOM.ObjectMeta.CreationTimestamp = metav1.Time{}
			filteredSBOM.ObjectMeta.UID = ""

			// update annotations with the correct imageID
			filteredSBOM.Annotations[helpersv1.ImageIDMetadataKey] = watchedContainer.ImageID
			filteredSBOM.Annotations[helpersv1.ImageTagMetadataKey] = watchedContainer.ImageTag

			for i := range filteredSBOM.Spec.Syft.ArtifactRelationships {
				watchedContainer.RelevantRelationshipsArtifactsByIdentifier[getRelationshipID(filteredSBOM.Spec.Syft.ArtifactRelationships[i])] = true
			}
			for i := range filteredSBOM.Spec.Syft.Files {
				watchedContainer.RelevantRealtimeFilesByIdentifier[filteredSBOM.Spec.Syft.Files[i].ID] = true
			}
			for i := range filteredSBOM.Spec.Syft.Artifacts {
				watchedContainer.RelevantArtifactsFilesByIdentifier[filteredSBOM.Spec.Syft.Artifacts[i].ID] = true
			}

			watchedContainer.SBOMSyftFiltered = filteredSBOM
		}
	}

	// if resource version is higher than in-memory, delete saved relevancy info
	if utils.Atoi(syftData.ResourceVersion) > watchedContainer.SBOMResourceVersion {
		logger.L().Debug("SBOM resource version is higher than the one in memory, parsing SBOM", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Int("in memory", watchedContainer.SBOMResourceVersion), helpers.Int("in storage", utils.Atoi(syftData.ResourceVersion)))

		for _, file := range syftData.Spec.Syft.Files {
			if _, ok := watchedContainer.RelevantRealtimeFilesByIdentifier[file.ID]; ok {
				watchedContainer.RelevantRealtimeFilesByIdentifier[file.ID] = false
			}
		}
		// save files, packages and relationships
		files := watchedContainer.SBOMSyftFiltered.Spec.Syft.Files
		packages := watchedContainer.SBOMSyftFiltered.Spec.Syft.Artifacts
		relationships := watchedContainer.SBOMSyftFiltered.Spec.Syft.ArtifactRelationships

		// copy spec and status
		watchedContainer.SBOMSyftFiltered.Spec = syftData.Spec
		watchedContainer.SBOMSyftFiltered.Status = syftData.Status

		// restore files, packages and relationships
		watchedContainer.SBOMSyftFiltered.Spec.Syft.Files = files
		watchedContainer.SBOMSyftFiltered.Spec.Syft.Artifacts = packages
		watchedContainer.SBOMSyftFiltered.Spec.Syft.ArtifactRelationships = relationships

		// update resource version
		watchedContainer.SBOMResourceVersion = utils.Atoi(syftData.ResourceVersion)
		newRelevantData = true
	}

	filterRelevantFilesInSBOM(watchedContainer, syftData.Spec.Syft, sbomFileRelevantMap, &newRelevantData)

	if !newRelevantData {
		return nil
	}

	if err = sc.storageClient.CreateFilteredSBOM(watchedContainer.SBOMSyftFiltered); err != nil {
		return fmt.Errorf("failed to store filtered SBOM: %w", err)
	}
	logger.L().Info("filtered SBOM has been stored successfully", helpers.String("containerID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.String("filtered SBOM", watchedContainer.SBOMSyftFiltered.Name))

	return nil
}

func filterRelevantFilesInSBOM(watchedContainer *utils.WatchedContainerData, syftDoc v1beta1.SyftDocument, sbomFileRelevantMap map[string]bool, newRelevantData *bool) {

	// filter relevant file list
	for i := range syftDoc.Files {
		// the .location.realPath is not the ID of the file, that's why the map identifier is the ID and not the path
		if _, k := watchedContainer.RelevantRealtimeFilesByIdentifier[syftDoc.Files[i].ID]; !k {
			if _, ok := sbomFileRelevantMap[syftDoc.Files[i].Location.RealPath]; ok {
				watchedContainer.SBOMSyftFiltered.Spec.Syft.Files = append(watchedContainer.SBOMSyftFiltered.Spec.Syft.Files, syftDoc.Files[i])
				watchedContainer.RelevantRealtimeFilesByIdentifier[syftDoc.Files[i].ID] = true
				*(newRelevantData) = true
			}
		}
	}

	if !*newRelevantData {
		return
	}

	// filter relevant relationships. A relationship is relevant if the child is a relevant file
	relationshipsArtifacts := make(map[string]bool, 0)
	for _, relationship := range syftDoc.ArtifactRelationships {
		if _, ok := watchedContainer.RelevantRelationshipsArtifactsByIdentifier[getRelationshipID(relationship)]; ok {
			continue
		}
		if _, ok := watchedContainer.RelevantRealtimeFilesByIdentifier[relationship.Child]; ok { // if the child is a relevant file
			relationshipsArtifacts[relationship.Parent] = true
			watchedContainer.RelevantRelationshipsArtifactsByIdentifier[getRelationshipID(relationship)] = true
			watchedContainer.SBOMSyftFiltered.Spec.Syft.ArtifactRelationships = append(watchedContainer.SBOMSyftFiltered.Spec.Syft.ArtifactRelationships, relationship)
		}
	}

	// Add children of relevant relationships (that the parent is not relevant)
	for _, relationship := range syftDoc.ArtifactRelationships {
		if _, ok := watchedContainer.RelevantRelationshipsArtifactsByIdentifier[getRelationshipID(relationship)]; ok {
			continue
		}
		if _, ok := relationshipsArtifacts[relationship.Child]; ok {
			relationshipsArtifacts[relationship.Parent] = true
			watchedContainer.RelevantRelationshipsArtifactsByIdentifier[getRelationshipID(relationship)] = true
			watchedContainer.SBOMSyftFiltered.Spec.Syft.ArtifactRelationships = append(watchedContainer.SBOMSyftFiltered.Spec.Syft.ArtifactRelationships, relationship)
		}
	}

	// filter relevant artifacts. An artifact is relevant if it is in the relevant relationships
	for _, artifact := range syftDoc.Artifacts {
		if _, ok := watchedContainer.RelevantArtifactsFilesByIdentifier[artifact.ID]; ok {
			continue
		}
		if _, ok := relationshipsArtifacts[artifact.ID]; ok {
			watchedContainer.SBOMSyftFiltered.Spec.Syft.Artifacts = append(watchedContainer.SBOMSyftFiltered.Spec.Syft.Artifacts, artifact)
			watchedContainer.RelevantArtifactsFilesByIdentifier[artifact.ID] = true
		}
	}

}

func (sc *SyftHandler) IncrementImageUse(imageID string) {

}
func (sc *SyftHandler) DecrementImageUse(imageID string) {

}

func getRelationshipID(relationship v1beta1.SyftRelationship) string {
	return fmt.Sprintf("%s/%s/%s", relationship.Parent, relationship.Child, relationship.Type)
}
