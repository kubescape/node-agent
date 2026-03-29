package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/aquilax/truncate"
	"github.com/cenkalti/backoff/v5"
	securejoin "github.com/cyphar/filepath-securejoin"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/distribution/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/kubescape/node-agent/pkg/sbommanager"
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/workerpool"
	"github.com/moby/sys/mountinfo"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/afero"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	_ "modernc.org/sqlite" // required for rpmdb and other features
)

const (
	digestDelim                   = "@"
	NodeNameMetadataKey           = "kubescape.io/node-name"
	ScannerMemoryLimitAnnotation  = "kubescape.io/scanner-memory-limit"
	maxScanRetries                = 3
	scannerReadinessCheckInterval = 5 * time.Second
	maxPendingScans               = 1000
)

// pendingScan holds the data needed to retry a container scan after the sidecar becomes ready.
type pendingScan struct {
	notif       containercollection.PubSubEvent
	mounts      []string
	imageStatus *runtime.ImageStatusResponse
	imageTag    string
	imageID     string
}

type SbomManager struct {
	appFs              afero.Fs
	cfg                config.Config
	ctx                context.Context
	hostRoot           string
	imageServiceClient runtime.ImageServiceClient
	k8sObjectCache     objectcache.K8sObjectCache
	pool               *workerpool.WorkerPool
	procDir            string
	processing         mapset.Set[string]
	storageClient      storage.SbomClient
	version            string
	scannerClient      sbomscanner.SBOMScannerClient
	scannerMemLimit    int64
	scanRetries        map[string]int // safe without mutex: only accessed from pool workers (pool size 1)
	pendingScans       map[string]pendingScan
	pendingOrder       []string
	pendingMu          sync.Mutex
	failureReporter    sbommanager.SbomFailureReporter // nil = no failure reporting (backward compat)
	accountID          string
	clusterName        string
}

var _ sbommanager.SbomManagerClient = (*SbomManager)(nil)

func CreateSbomManager(ctx context.Context, cfg config.Config, socketPath string, storageClient storage.SbomClient, k8sObjectCache objectcache.K8sObjectCache, scannerClient sbomscanner.SBOMScannerClient, failureReporter sbommanager.SbomFailureReporter, accountID, clusterName string) (*SbomManager, error) {
	// read HOST_ROOT from env
	hostRoot, exists := os.LookupEnv("HOST_ROOT")
	if !exists {
		hostRoot = "/host"
	}
	// use securejoin to join the two, add proc and store in procDir
	procDir, err := securejoin.SecureJoin(hostRoot, "/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to get proc dir: %w", err)
	}
	// connect to CRI socket
	conn, _ := grpc.Dial(
		socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	var scannerMemLimit int64
	if memStr, ok := os.LookupEnv("SCANNER_MEMORY_LIMIT"); ok {
		scannerMemLimit, _ = strconv.ParseInt(memStr, 10, 64)
	}

	sm := &SbomManager{
		appFs:              afero.NewOsFs(),
		cfg:                cfg,
		ctx:                ctx,
		hostRoot:           hostRoot,
		imageServiceClient: runtime.NewImageServiceClient(conn),
		k8sObjectCache:     k8sObjectCache,
		pool:               workerpool.New(1),
		procDir:            procDir,
		processing:         mapset.NewSet[string](),
		storageClient:      storageClient,
		version:            packageVersion("github.com/anchore/syft"),
		scannerClient:      scannerClient,
		scannerMemLimit:    scannerMemLimit,
		scanRetries:        make(map[string]int),
		pendingScans:       make(map[string]pendingScan),
		failureReporter:    failureReporter,
		accountID:          accountID,
		clusterName:        clusterName,
	}
	if scannerClient != nil {
		sm.startScannerReadinessWatcher()
	}
	return sm, nil
}

func (s *SbomManager) getImageStatus(imageID string) (*runtime.ImageStatusResponse, error) {
	return s.imageServiceClient.ImageStatus(context.Background(), &runtime.ImageStatusRequest{
		Image:   &runtime.ImageSpec{Image: imageID},
		Verbose: true,
	})
}

func (s *SbomManager) getMountedVolumes(pid string) ([]string, error) {
	f, err := s.appFs.Open(filepath.Join(s.procDir, pid, "mountinfo"))
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/%s/mountinfo: %w", pid, err)
	}
	defer func() {
		_ = f.Close()
	}()
	mounts, err := mountinfo.GetMountsFromReader(f, func(info *mountinfo.Info) (skip, stop bool) {
		if info.FSType == "overlay" {
			return false, true
		}
		return true, false
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get mounts: %w", err)
	}
	for _, option := range strings.Split(mounts[0].VFSOptions, ",") {
		if strings.HasPrefix(option, "lowerdir=") {
			var volumes []string
			for _, volume := range strings.Split(option[9:], ":") {
				// FIXME this is a workaround
				if !strings.HasPrefix(volume, "/") {
					volume = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/" + volume
				}
				volumes = append(volumes, filepath.Join(s.hostRoot, volume))
			}
			return volumes, nil
		}
	}
	return nil, fmt.Errorf("failed to find lowerdir in %s", mounts[0].VFSOptions)
}

func (s *SbomManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// only consider container start events
	if notif.Type != containercollection.EventTypeAddContainer {
		return
	}
	if utils.IsHostContainer(notif.Container) {
		return
	}
	if notif.Container.Runtime.ContainerImageName == "" {
		logger.L().Ctx(s.ctx).Debug("SbomManager - skipping container with empty image name",
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("container ID", notif.Container.Runtime.ContainerID))
		return
	}
	// check if the container should be ignored
	if s.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		return
	}
	// get container mounts
	pid := strconv.Itoa(int(notif.Container.ContainerPid()))
	mounts, err := s.getMountedVolumes(pid)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to get mounted volumes",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName))
		return
	}
	// get image layers
	imageStatus, err := s.getImageStatus(notif.Container.Runtime.ContainerImageName) // use original name to ask the CRI
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to get image layers",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName))
		return
	}
	// enqueue the container for processing
	s.pool.Submit(func() {
		s.processContainer(notif, mounts, imageStatus)
	}, utils.FuncName(s.processContainer))
}

func (s *SbomManager) processContainer(notif containercollection.PubSubEvent, mounts []string, imageStatus *runtime.ImageStatusResponse) {
	sharedData, err := s.waitForSharedContainerData(notif.Container.Runtime.ContainerID)
	if err != nil {
		logger.L().Error("SbomManager - container not found in shared data",
			helpers.String("container ID", notif.Container.Runtime.ContainerID))
		return
	}
	s.processContainerWithMetadata(notif, mounts, imageStatus, sharedData.ImageTag, sharedData.ImageID)
}

func (s *SbomManager) processContainerWithMetadata(notif containercollection.PubSubEvent, mounts []string, imageStatus *runtime.ImageStatusResponse, imageTag, imageID string) {
	// prepare SBOM name
	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to generate SBOM name",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("imageName", imageTag),
			helpers.String("imageDigest", imageID))
		return
	}
	// try to create a SBOM with initializing status to reserve our slot
	normalizedID := normalizeImageID(imageTag, imageID)
	wipSbom := &v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbomName,
			Annotations: map[string]string{
				helpersv1.ImageIDMetadataKey:     normalizedID,
				helpersv1.ImageTagMetadataKey:    imageTag,
				helpersv1.StatusMetadataKey:      helpersv1.Initializing,
				NodeNameMetadataKey:              s.cfg.NodeName,
				helpersv1.ToolVersionMetadataKey: s.version,
			},
			Labels: labelsFromImageID(normalizedID),
		},
	}
	wipSbom, err = s.storageClient.CreateSBOM(wipSbom)
	switch {
	case k8serrors.IsAlreadyExists(err):
		// get the existing SBOM metadata and check if it is ready or being processed by another node
		// wipSbom is empty because of the error so we can reuse the pointer
		wipSbom, err = s.storageClient.GetSBOMMeta(sbomName)
		if err != nil {
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to get existing SBOM metadata",
				helpers.Error(err),
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			return
		}
		switch {
		case wipSbom.Annotations[helpersv1.StatusMetadataKey] == helpersv1.TooLarge:
			if recordedLimit := wipSbom.Annotations[ScannerMemoryLimitAnnotation]; recordedLimit != "" {
				if recordedLimit != fmt.Sprintf("%d", s.scannerMemLimit) && s.scannerMemLimit > 0 {
					logger.L().Debug("SbomManager - scanner memory limit changed, retrying previously failed SBOM",
						helpers.String("sbomName", sbomName),
						helpers.String("recordedLimit", recordedLimit),
						helpers.Int("currentLimit", int(s.scannerMemLimit)))
					break
				}
			}
			logger.L().Debug("SbomManager - image is too large for SBOM processing, skipping",
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName),
				helpers.String("nodeName", wipSbom.Annotations[NodeNameMetadataKey]))
			return
		case wipSbom.Annotations[helpersv1.StatusMetadataKey] == helpersv1.Learning:
			// only skip if the SBOM was created with the same version of tool
			if wipSbom.Annotations[helpersv1.ToolVersionMetadataKey] == s.version {
				logger.L().Debug("SbomManager - SBOM is already created, skipping",
					helpers.String("namespace", notif.Container.K8s.Namespace),
					helpers.String("pod", notif.Container.K8s.PodName),
					helpers.String("container", notif.Container.K8s.ContainerName),
					helpers.String("sbomName", sbomName))
				return
			}
			logger.L().Debug("SbomManager - SBOM was created with an different version of tool, recreating it",
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName),
				helpers.String("got version", wipSbom.Annotations[helpersv1.ToolVersionMetadataKey]),
				helpers.String("expected version", s.version))
			// update the version of the tool
			wipSbom.Annotations[helpersv1.ToolVersionMetadataKey] = s.version
			// continue to create SBOM
		case wipSbom.Annotations[NodeNameMetadataKey] != s.cfg.NodeName:
			logger.L().Debug("SbomManager - SBOM is already being processed by another node, skipping",
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName),
				helpers.String("nodeName", wipSbom.Annotations[NodeNameMetadataKey]))
			return
		case s.processing.Contains(sbomName):
			logger.L().Debug("SbomManager - SBOM is already being processed by this node, skipping",
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			return
		default:
			logger.L().Debug("SbomManager - SBOM processing was interrupted, retrying",
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			// continue to create SBOM
		}
	case err != nil:
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to create empty SBOM before processing",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		return
	default:
		logger.L().Debug("SbomManager - created empty SBOM, start processing",
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		// continue to create SBOM
	}
	// track SBOM as processing in internal state to prevent concurrent processing
	s.processing.Add(sbomName)
	defer s.processing.Remove(sbomName)
	var syftDoc v1beta1.SyftDocument
	scanStart := time.Now()

	if s.scannerClient != nil && s.scannerClient.Ready() {
		sbomScannerReady.Set(1)
		// sidecar path: delegate SBOM creation to the scanner sidecar
		imageStatusBytes, marshalErr := json.Marshal(imageStatus)
		if marshalErr != nil {
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to marshal image status",
				helpers.Error(marshalErr),
				helpers.String("sbomName", sbomName))
			return
		}
		scanTimeout := 16 * time.Minute // slightly longer than server-side timeout as a transport-level safety net
		scanCtx, scanCancel := context.WithTimeout(s.ctx, scanTimeout)
		defer scanCancel()
		result, scanErr := s.scannerClient.CreateSBOM(scanCtx, sbomscanner.ScanRequest{
			ImageID:             normalizedID,
			ImageTag:            imageTag,
			LayerPaths:          mounts,
			ImageStatus:         imageStatusBytes,
			MaxImageSize:        s.cfg.MaxImageSize,
			MaxSBOMSize:         int32(s.cfg.MaxSBOMSize),
			EnableEmbeddedSBOMs: s.cfg.EnableEmbeddedSboms,
			Timeout:             15 * time.Minute,
		})
		if scanErr != nil {
			scanDuration := time.Since(scanStart).Seconds()
			if errors.Is(scanErr, sbomscanner.ErrScannerCrashed) {
				sbomScanTotal.WithLabelValues("oom_killed").Inc()
				sbomScanDuration.WithLabelValues("oom_killed").Observe(scanDuration)
				sbomScannerRestartsTotal.Inc()
				sbomScannerReady.Set(0)
				s.handleScannerCrash(sbomName, wipSbom, notif, scanErr, sharedData.ImageTag, imageID)
				return
			}
			sbomScanTotal.WithLabelValues("error").Inc()
			sbomScanDuration.WithLabelValues("error").Observe(scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - sidecar scan failed",
				helpers.Error(scanErr),
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			s.reportFailure(notif, sharedData.ImageTag, imageID, scanfailure.ReasonSBOMGenerationFailed, scanErr)
			return
		}
		sbomScanTotal.WithLabelValues("success").Inc()
		sbomScanDuration.WithLabelValues("success").Observe(time.Since(scanStart).Seconds())
		delete(s.scanRetries, sbomName)
		syftDoc = result.SyftDocument
	} else if s.scannerClient != nil {
		sbomScannerReady.Set(0)
		// sidecar configured but not ready — queue for retry when it becomes ready
		logger.L().Debug("SbomManager - scanner sidecar not ready, queuing scan for retry",
			helpers.String("sbomName", sbomName))
		s.pendingMu.Lock()
		key := sbomName + "|" + normalizedID
		if _, ok := s.pendingScans[key]; !ok {
			if len(s.pendingOrder) >= maxPendingScans {
				// evict oldest
				oldestKey := s.pendingOrder[0]
				s.pendingOrder = s.pendingOrder[1:]
				delete(s.pendingScans, oldestKey)
			}
			s.pendingOrder = append(s.pendingOrder, key)
		}
		s.pendingScans[key] = pendingScan{
			notif:       notif,
			mounts:      mounts,
			imageStatus: imageStatus,
			imageTag:    imageTag,
			imageID:     imageID,
		}
		s.pendingMu.Unlock()
		return
	} else {
		// in-process fallback (current behavior)
		src, srcErr := syftutil.NewSource(imageTag, imageID, normalizedID, imageStatus, mounts, s.cfg.MaxImageSize)
		if srcErr != nil {
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to create image source",
				helpers.Error(srcErr),
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			if errors.Is(srcErr, syftutil.ErrImageTooLarge) {
				delete(wipSbom.Annotations, NodeNameMetadataKey)
				wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
				if _, replaceErr := s.storageClient.ReplaceSBOM(wipSbom); replaceErr != nil {
					logger.L().Ctx(s.ctx).Error("SbomManager - failed to persist TooLarge SBOM",
						helpers.Error(replaceErr),
						helpers.String("sbomName", sbomName))
				}
				s.reportFailure(notif, sharedData.ImageTag, imageID, scanfailure.ReasonImageTooLarge, srcErr)
			} else {
				s.reportFailure(notif, sharedData.ImageTag, imageID, scanfailure.ReasonSBOMGenerationFailed, srcErr)
			}
			return
		}
		sbomCfg := syft.DefaultCreateSBOMConfig()
		sbomCfg.ToolName = "syft"
		sbomCfg.ToolVersion = s.version
		if s.cfg.EnableEmbeddedSboms {
			sbomCfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
		}
		syftSBOM, syftErr := syft.CreateSBOM(context.Background(), src, sbomCfg)
		if syftErr != nil {
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to generate SBOM",
				helpers.Error(syftErr),
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			s.reportFailure(notif, sharedData.ImageTag, imageID, scanfailure.ReasonSBOMGenerationFailed, syftErr)
			return
		}
		v1beta1.StripSBOM(syftSBOM)
		syftDoc = syftutil.ToSyftDocument(syftSBOM)
	}

	// prepare the SBOM
	delete(wipSbom.Annotations, NodeNameMetadataKey)
	wipSbom.Spec.Metadata.Report.CreatedAt = wipSbom.CreationTimestamp
	wipSbom.Spec.Metadata.Tool.Name = "syft"
	wipSbom.Spec.Metadata.Tool.Version = s.version
	wipSbom.Spec.Syft = syftDoc
	// check the size of the SBOM
	sz := size.Of(wipSbom)
	wipSbom.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > s.cfg.MaxSBOMSize {
		logger.L().Debug("SbomManager - SBOM exceeds size limit",
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName),
			helpers.Int("maxImageSize", s.cfg.MaxSBOMSize),
			helpers.Int("size", sz))
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
		// clear the spec
		wipSbom.Spec = v1beta1.SBOMSyftSpec{}
		s.reportFailure(notif, sharedData.ImageTag, imageID, scanfailure.ReasonSBOMTooLarge, nil)
	} else {
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Learning
	}
	// save the SBOM
	_, err = s.storageClient.ReplaceSBOM(wipSbom)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to save SBOM",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		s.reportFailure(notif, sharedData.ImageTag, imageID, scanfailure.ReasonSBOMStorageFailed, err)
		return
	}
	logger.L().Debug("SbomManager - saved SBOM after successful processing",
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("sbomName", sbomName))
}

func (s *SbomManager) waitForSharedContainerData(containerID string) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*objectcache.WatchedContainerData, error) {
		if sharedData := s.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

func (s *SbomManager) handleScannerCrash(sbomName string, wipSbom *v1beta1.SBOMSyft, notif containercollection.PubSubEvent, scanErr error, imageTag, imageID string) {
	s.scanRetries[sbomName]++
	retryCount := s.scanRetries[sbomName]

	logger.L().Error("SbomManager - SBOM scanner sidecar crashed during scan",
		helpers.Error(scanErr),
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("sbomName", sbomName),
		helpers.Int("retryCount", retryCount),
		helpers.Int("maxRetries", maxScanRetries))

	if retryCount >= maxScanRetries {
		delete(wipSbom.Annotations, NodeNameMetadataKey)
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
		wipSbom.Annotations[ScannerMemoryLimitAnnotation] = fmt.Sprintf("%d", s.scannerMemLimit)
		wipSbom.Spec = v1beta1.SBOMSyftSpec{}
		if _, replaceErr := s.storageClient.ReplaceSBOM(wipSbom); replaceErr != nil {
			logger.L().Error("SbomManager - failed to mark SBOM as TooLarge after scanner crashes",
				helpers.Error(replaceErr),
				helpers.String("sbomName", sbomName))
		}
		// Report OOM regardless of persist success — the user should know the scan failed
		s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonScannerOOMKilled, scanErr)
		delete(s.scanRetries, sbomName)
	}
}

func (s *SbomManager) startScannerReadinessWatcher() {
	go func() {
		ticker := time.NewTicker(scannerReadinessCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.pendingMu.Lock()
				hasWork := len(s.pendingOrder) > 0
				s.pendingMu.Unlock()
				if !hasWork || !s.scannerClient.Ready() {
					continue
				}
				s.drainPendingScans()
			}
		}
	}()
}

func (s *SbomManager) drainPendingScans() {
	s.pendingMu.Lock()
	pendingOrder := s.pendingOrder
	pendingScans := s.pendingScans
	s.pendingOrder = nil
	s.pendingScans = make(map[string]pendingScan)
	s.pendingMu.Unlock()

	if len(pendingOrder) == 0 {
		return
	}

	logger.L().Debug("SbomManager - scanner sidecar ready, resubmitting queued scans",
		helpers.Int("count", len(pendingOrder)))

	for _, key := range pendingOrder {
		scan := pendingScans[key]
		s.pool.Submit(func() {
			s.processContainerWithMetadata(scan.notif, scan.mounts, scan.imageStatus, scan.imageTag, scan.imageID)
		}, utils.FuncName(s.processContainerWithMetadata))
	}
}

// reportFailure sends a scan failure report to the backend via the failure reporter.
// Fire-and-forget: errors are logged, never propagated. Safe to call with nil reporter.
func (s *SbomManager) reportFailure(notif containercollection.PubSubEvent, imageTag, imageID, reason string, scanErr error) {
	if s.failureReporter == nil {
		return
	}

	report := scanfailure.ScanFailureReport{
		CustomerGUID:  s.accountID,
		ImageTag:      imageTag,
		ImageHash:     imageID,
		FailureCase:   scanfailure.ScanFailureSBOMGeneration,
		FailureReason: reason,
		Timestamp:     time.Now(),
		Workloads: []scanfailure.WorkloadIdentifier{{
			ClusterName:   s.clusterName,
			Namespace:     notif.Container.K8s.Namespace,
			WorkloadKind:  "Pod",
			WorkloadName:  notif.Container.K8s.PodName,
			ContainerName: notif.Container.K8s.ContainerName,
		}},
	}
	if scanErr != nil {
		report.Error = scanErr.Error()
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.failureReporter.ReportSbomFailure(ctx, report); err != nil {
			logger.L().Warning("failed to report SBOM failure",
				helpers.Error(err),
				helpers.String("reason", reason),
				helpers.String("imageTag", imageTag))
		}
	}()
}

func labelsFromImageID(imageID string) map[string]string {
	labels := map[string]string{}
	ref, err := reference.Parse(imageID)
	if err != nil {
		return labels
	}
	if named, ok := ref.(reference.Named); ok {
		labels[helpersv1.ImageIDMetadataKey] = sanitize(named.String())
		labels[helpersv1.ImageNameMetadataKey] = sanitize(named.Name())
	}
	if tagged, ok := ref.(reference.Tagged); ok {
		labels[helpersv1.ImageTagMetadataKey] = sanitize(tagged.Tag())
	}
	// prune invalid labels
	for key, value := range labels {
		if errs := validation.IsDNS1123Label(value); len(errs) != 0 {
			delete(labels, key)
		}
	}
	return labels
}

func normalizeImageID(imageName, imageDigest string) string {
	// registry scanning doesn't provide imageID, so we use imageTag as a reference
	if imageDigest == "" {
		return imageName
	}

	// try to parse imageID as a full digest
	if newDigest, err := name.NewDigest(imageDigest); err == nil {
		return newDigest.String()
	}
	// if it's not a full digest, we need to use imageTag as a reference
	tag, err := name.ParseReference(imageName)
	if err != nil {
		return ""
	}

	// and append imageID as a digest
	parts := strings.Split(imageDigest, digestDelim)
	// filter garbage
	if len(parts) > 1 {
		imageDigest = parts[len(parts)-1]
	}
	prefix := digest.Canonical.String() + ":"
	if !strings.HasPrefix(imageDigest, prefix) {
		// add missing prefix
		imageDigest = prefix + imageDigest
	}
	// docker.io is parsed as index.docker.io
	normalizedImageName := strings.Replace(tag.Context().String(), "index.docker.io", "docker.io", 1)
	return normalizedImageName + digestDelim + imageDigest
}

func packageVersion(name string) string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range bi.Deps {
			if dep.Path == name {
				return dep.Version
			}
		}
	}
	return "unknown"
}

var offendingChars = regexp.MustCompile("[@:/ ._]")

func sanitize(s string) string {
	s2 := truncate.Truncate(offendingChars.ReplaceAllString(s, "-"), 63, "", truncate.PositionEnd)
	// remove trailing dash
	if len(s2) > 0 && s2[len(s2)-1] == '-' {
		return s2[:len(s2)-1]
	}
	return s2
}
