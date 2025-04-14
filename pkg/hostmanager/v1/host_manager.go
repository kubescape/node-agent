package v1

import (
	"context"
	"fmt"
	"os"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostmanager"
	sbommanagerv1 "github.com/kubescape/node-agent/pkg/sbommanager/v1"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spf13/afero"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

type HostManager struct {
	appFs         afero.Fs
	cfg           config.Config
	ctx           context.Context
	hostRoot      string
	storageClient storage.StorageClient
	version       string
}

var _ hostmanager.HostManagerClient = (*HostManager)(nil)

func CreateHostManager(ctx context.Context, cfg config.Config, storageClient storage.StorageClient) (*HostManager, error) {
	// read HOST_ROOT from env
	hostRoot, exists := os.LookupEnv("HOST_ROOT")
	if !exists {
		hostRoot = "/host"
	}
	return &HostManager{
		appFs:         afero.NewOsFs(),
		cfg:           cfg,
		ctx:           ctx,
		hostRoot:      hostRoot,
		storageClient: storageClient,
	}, nil
}

func (h *HostManager) Start(ctx context.Context) {
	logger.L().Info("starting HostManager")
	// ensure node SBOM exists
	go h.createNodeSBOM(ctx)
}

func (h *HostManager) createNodeSBOM(ctx context.Context) {
	sbomName := h.cfg.NodeName
	nodeSbom, err := h.storageClient.GetSBOMMeta(sbomName)
	switch {
	case err == nil:
		switch {
		case nodeSbom.Annotations[helpersv1.StatusMetadataKey] == helpersv1.TooLarge:
			logger.L().Info("HostManager - node SBOM is too large for processing, skipping",
				helpers.String("sbomName", sbomName))
			return
		case nodeSbom.Annotations[helpersv1.ToolVersionMetadataKey] == h.version:
			logger.L().Info("HostManager - node SBOM already exists",
				helpers.String("sbomName", sbomName))
			return
			// TODO how to detect if the node packages have been updated?
		}
		logger.L().Info("HostManager - node SBOM exists but version is different, updating it",
			helpers.String("sbomName", sbomName))
		// continue to create SBOM
	case k8serrors.IsNotFound(err):
		logger.L().Info("HostManager - node SBOM not found, creating a new one",
			helpers.String("sbomName", sbomName))
		// continue to create SBOM
	default:
		logger.L().Ctx(ctx).Error("HostManager - failed to get node SBOM",
			helpers.Error(err),
			helpers.String("sbomName", sbomName))
		return
	}
	// prepare image source
	sourceConfig := directorysource.Config{
		Path: h.hostRoot,
		Base: h.hostRoot,
		Exclude: source.ExcludeConfig{
			Paths: []string{
				"./run/*",
				"./var/lib/containerd/*",
				"./var/lib/containers/*",
				"./var/lib/docker/*",
			},
		},
		Alias: source.Alias{},
	}
	src, err := directorysource.New(sourceConfig)
	if err != nil {
		logger.L().Ctx(ctx).Error("HostManager - failed to create node SBOM source",
			helpers.Error(err),
			helpers.String("sbomName", sbomName))
		return
	}
	// create the SBOM
	sbomConfig := syft.DefaultCreateSBOMConfig()
	sbomConfig.ToolName = "syft"
	sbomConfig.ToolVersion = h.version
	syftSBOM, err := syft.CreateSBOM(context.Background(), src, sbomConfig)
	if err != nil {
		logger.L().Ctx(ctx).Error("HostManager - failed to generate node SBOM",
			helpers.Error(err),
			helpers.String("sbomName", sbomName))
		return
	}
	// prepare the SBOM
	nodeSbom = &v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbomName,
			Annotations: map[string]string{
				helpersv1.ToolVersionMetadataKey: h.version,
			},
			Labels: map[string]string{
				helpersv1.ArtifactTypeMetadataKey: helpersv1.NodeArtifactType,
			},
		},
	}
	nodeSbom.Spec.Syft = sbommanagerv1.ToSyftDocument(syftSBOM)
	// check the size of the SBOM
	sz := size.Of(nodeSbom)
	nodeSbom.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > h.cfg.MaxSBOMSize {
		logger.L().Info("HostManager - SBOM exceeds size limit",
			helpers.Int("maxImageSize", h.cfg.MaxSBOMSize),
			helpers.Int("size", sz),
			helpers.String("sbomName", sbomName))
		nodeSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
	} else {
		nodeSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Ready
	}
	// save the SBOM
	_, err = h.storageClient.CreateSBOM(nodeSbom)
	switch {
	case k8serrors.IsAlreadyExists(err), k8serrors.IsForbidden(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			result, getErr := h.storageClient.GetSBOMMeta(sbomName)
			if getErr != nil {
				return getErr
			}
			// update the SBOM with the new data
			mergeMaps(result.Annotations, nodeSbom.Annotations)
			mergeMaps(result.Labels, nodeSbom.Labels)
			result.Spec = nodeSbom.Spec
			// try to send the updated object
			_, updateErr := h.storageClient.ReplaceSBOM(result)
			return updateErr
		})
		if retryErr != nil {
			logger.L().Ctx(ctx).Error("HostManager - failed to update node SBOM",
				helpers.Error(retryErr),
				helpers.String("sbomName", sbomName))
			return
		}
	case err != nil:
		logger.L().Ctx(ctx).Error("HostManager - failed to create node SBOM",
			helpers.Error(err),
			helpers.String("sbomName", sbomName))
		return
	}
	logger.L().Info("HostManager - saved SBOM after successful processing",
		helpers.String("sbomName", sbomName))
}

// mergeMaps merges new into existing, overwriting existing keys with new values
func mergeMaps(existing, new map[string]string) {
	for k, v := range new {
		existing[k] = v
	}
}
