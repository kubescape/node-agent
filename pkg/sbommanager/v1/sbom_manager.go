package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/aquilax/truncate"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/cenkalti/backoff/v5"
	securejoin "github.com/cyphar/filepath-securejoin"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/distribution/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/golang-lru/v2/expirable"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
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
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
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
	maxFailureRetryEntries        = 1000
	failureRetryTTL               = 30 * time.Minute
	// crashLoopRetryTTL is deliberately much longer than failureRetryTTL: a sidecar OOM crash
	// stalls the shared scanner for every image on the node, so a chronically-crashing image
	// with restarts spaced further apart than failureRetryTTL must still eventually be pinned,
	// or it can stall the node's scanning indefinitely.
	crashLoopRetryTTL = 24 * time.Hour
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
	// failureRetries is the combined per-sbomName failure budget shared by handleGenericFailure
	// and handleScannerCrash via incrementFailureCount, bounding total mixed-category attempts
	// to maxScanRetries. TTL'd so short-lived images don't leak entries; a failure gap wider than
	// failureRetryTTL resets the count, so this bounds a tight failure cadence, not every possible
	// one. Crossing this threshold alone never produces TooLarge -- see crashLoopRetries.
	failureRetries *expirable.LRU[string, int]
	// crashLoopRetries counts scanner crashes per sbomName (handleScannerCrash only, unaffected
	// by interleaved generic failures), on crashLoopRetryTTL rather than failureRetryTTL, so it
	// is the sole path to a TooLarge classification and survives the wider gaps a slow-cadence
	// crash loop needs.
	crashLoopRetries *expirable.LRU[string, int]
	pendingScans     map[string]pendingScan
	pendingOrder     []string
	pendingMu        sync.Mutex
	failureReporter  sbommanager.SbomFailureReporter
	metrics          metricsmanager.MetricsManager
}

var _ sbommanager.SbomManagerClient = (*SbomManager)(nil)

func CreateSbomManager(ctx context.Context, cfg config.Config, socketPath string, storageClient storage.SbomClient, k8sObjectCache objectcache.K8sObjectCache, scannerClient sbomscanner.SBOMScannerClient, failureReporter sbommanager.SbomFailureReporter, metrics metricsmanager.MetricsManager) (*SbomManager, error) {
	if metrics == nil {
		metrics = &metricsmanager.MetricsNoop{}
	}
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
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
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
		failureRetries:     expirable.NewLRU[string, int](maxFailureRetryEntries, nil, failureRetryTTL),
		crashLoopRetries:   expirable.NewLRU[string, int](maxFailureRetryEntries, nil, crashLoopRetryTTL),
		pendingScans:       make(map[string]pendingScan),
		failureReporter:    failureReporter,
		metrics:            metrics,
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
	if len(mounts) == 0 {
		// No overlay mount found — container is using a non-overlay snapshotter (e.g. ZFS, btrfs).
		// /proc/<pid>/root is a kernel-provided path that exposes the container's merged root
		// filesystem on the host regardless of the underlying snapshotter.
		return []string{filepath.Join(s.procDir, pid, "root")}, nil
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
	// wipSbomHadContent is true only when we're about to reprocess an SBOM that previously
	// completed successfully (the Learning case below). It exists solely to keep a
	// content-bearing SBOM from ever being marked TooLarge on the reprocess path: unlike
	// Incomplete, TooLarge is a one-way door in the storage layer -- GuaranteedUpdate
	// silently drops every future write once status=too-large is set, so persisting it here
	// (with the real Spec still attached, since PatchSBOMAnnotations never clears it) would
	// leave the SBOM permanently frozen with its old content, unfixable by any later version.
	// Incomplete has no such short-circuit and stays safely retryable, so it's used instead.
	var wipSbomHadContent bool
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
			if !s.shouldRetryAtCurrentVersion(wipSbom, sbomName, notif,
				"SBOM is already created, skipping",
				"SBOM was created with an different version of tool, recreating it") {
				return
			}
			wipSbomHadContent = true
			// continue to create SBOM
		case wipSbom.Annotations[helpersv1.StatusMetadataKey] == helpersv1.Incomplete:
			if !s.shouldRetryAtCurrentVersion(wipSbom, sbomName, notif,
				"SBOM generation previously failed with this tool version, skipping",
				"SBOM generation previously failed with a different tool version, retrying") {
				return
			}
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
		s.metrics.SetSBOMScannerReady(true)
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
			scanDuration := time.Since(scanStart)
			if errors.Is(scanErr, sbomscanner.ErrScannerCrashed) {
				s.metrics.ReportSBOMScan("oom_killed")
				s.metrics.ObserveSBOMScanDuration("oom_killed", scanDuration)
				s.metrics.ReportSBOMScannerRestart()
				s.metrics.SetSBOMScannerReady(false)
				s.handleScannerCrash(sbomName, notif, scanErr, imageTag, imageID, wipSbomHadContent)
				return
			}
			s.metrics.ReportSBOMScan("error")
			s.metrics.ObserveSBOMScanDuration("error", scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - sidecar scan failed",
				helpers.Error(scanErr),
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName))
			s.handleGenericFailure(sbomName)
			s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonSBOMGenerationFailed, scanErr)
			return
		}
		s.metrics.ReportSBOMScan("success")
		s.metrics.ObserveSBOMScanDuration("success", time.Since(scanStart))
		syftDoc = result.SyftDocument
	} else if s.scannerClient != nil {
		s.metrics.SetSBOMScannerReady(false)
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
				if wipSbomHadContent {
					// don't let a content-bearing SBOM reach the TooLarge one-way door; treat
					// it as a generic (retryable, eventually Incomplete) failure instead.
					s.handleGenericFailure(sbomName)
				} else {
					s.markSBOMStatus(sbomName, helpersv1.TooLarge, nil)
				}
				s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonImageTooLarge, srcErr)
			} else {
				s.handleGenericFailure(sbomName)
				s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonSBOMGenerationFailed, srcErr)
			}
			return
		}
		sbomCfg := syft.DefaultCreateSBOMConfig()
		sbomCfg.ToolName = "syft"
		sbomCfg.ToolVersion = s.version
		sbomCfg = sbomCfg.WithCatalogerSelection(
			cataloging.NewSelectionRequest().WithRemovals(
				"file-digest-cataloger",
				"file-metadata-cataloger",
				"file-executable-cataloger",
			),
		)
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
			s.handleGenericFailure(sbomName)
			s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonSBOMGenerationFailed, syftErr)
			return
		}
		v1beta1.StripSBOM(syftSBOM)
		syftDoc = syftutil.ToSyftDocument(syftSBOM)
	}

	// prepare the SBOM
	s.failureRetries.Remove(sbomName)
	s.crashLoopRetries.Remove(sbomName)
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
		s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonSBOMTooLarge, nil)
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
		s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonSBOMStorageFailed, err)
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

// handleScannerCrash responds to repeated sidecar OOM crashes while scanning the same image.
// hadContent must be true when the SBOM being reprocessed previously completed successfully
// (see the wipSbomHadContent doc comment in processContainerWithMetadata) -- in that case the
// terminal status is Incomplete rather than TooLarge, since TooLarge is a one-way door in the
// storage layer that would permanently freeze the SBOM's existing content.
//
// TooLarge is only reachable via crashLoopRetries, the dedicated crash-only backstop -- a pin
// triggered by the shared failureRetries budget alone (which may include generic failures) always
// falls back to Incomplete, since a threshold crossing that includes even one non-crash failure
// isn't evidence the image doesn't fit in the scanner's memory limit.
func (s *SbomManager) handleScannerCrash(sbomName string, notif containercollection.PubSubEvent, scanErr error, imageTag, imageID string, hadContent bool) {
	retryCount := s.incrementFailureCount(sbomName)
	crashLoopCount := s.incrementCrashLoopCount(sbomName)

	logger.L().Error("SbomManager - SBOM scanner sidecar crashed during scan",
		helpers.Error(scanErr),
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("sbomName", sbomName),
		helpers.Int("retryCount", retryCount),
		helpers.Int("crashLoopCount", crashLoopCount),
		helpers.Int("maxRetries", maxScanRetries))

	crashLoopTriggered := crashLoopCount >= maxScanRetries
	if retryCount < maxScanRetries && !crashLoopTriggered {
		return
	}

	if !hadContent && crashLoopTriggered {
		s.markSBOMStatus(sbomName, helpersv1.TooLarge, map[string]any{
			ScannerMemoryLimitAnnotation: fmt.Sprintf("%d", s.scannerMemLimit),
		})
	} else {
		s.markSBOMStatus(sbomName, helpersv1.Incomplete, nil)
	}
	// Report OOM regardless of persist success — the user should know the scan failed
	s.reportFailure(notif, imageTag, imageID, scanfailure.ReasonScannerOOMKilled, scanErr)
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

// markSBOMStatus persists the SBOM's terminal status (e.g. TooLarge, Incomplete) so a later
// container start for the same image is handled by the matching case in
// processContainerWithMetadata instead of retrying and failing indefinitely. It also records
// the currently-running tool version alongside the status, since that's what determined the
// outcome -- the Learning/Incomplete cases' version check relies on this being accurate.
func (s *SbomManager) markSBOMStatus(sbomName, status string, extraAnnotations map[string]any) {
	annotations := map[string]any{
		NodeNameMetadataKey:              nil, // no longer owned by this node
		helpersv1.StatusMetadataKey:      status,
		helpersv1.ToolVersionMetadataKey: s.version,
	}
	maps.Copy(annotations, extraAnnotations)
	if _, err := s.storageClient.PatchSBOMAnnotations(sbomName, annotations); err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to persist SBOM status",
			helpers.Error(err),
			helpers.String("sbomName", sbomName),
			helpers.String("status", status))
	}
}

// shouldRetryAtCurrentVersion checks a status-gated SBOM's recorded tool version against the
// running version. If they match, it logs skipMsg and returns false (the caller should skip
// reprocessing). Otherwise it logs retryMsg, updates the tool-version annotation, and returns
// true (the caller should continue to reprocess).
func (s *SbomManager) shouldRetryAtCurrentVersion(wipSbom *v1beta1.SBOMSyft, sbomName string, notif containercollection.PubSubEvent, skipMsg, retryMsg string) bool {
	if wipSbom.Annotations[helpersv1.ToolVersionMetadataKey] == s.version {
		logger.L().Debug(skipMsg,
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		return false
	}
	logger.L().Debug(retryMsg,
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("sbomName", sbomName),
		helpers.String("got version", wipSbom.Annotations[helpersv1.ToolVersionMetadataKey]),
		helpers.String("expected version", s.version))
	wipSbom.Annotations[helpersv1.ToolVersionMetadataKey] = s.version
	return true
}

// incrementFailureCount increments the shared per-sbomName failure budget (used by both
// handleGenericFailure and handleScannerCrash) and returns the new count. The entry is removed
// once count reaches maxScanRetries so the pin only fires once per threshold crossing -- a fresh
// budget afterward comes from a successful scan (which resets it explicitly on the success path)
// or the TTL simply expiring; a tool-version bump alone does not touch this LRU.
func (s *SbomManager) incrementFailureCount(sbomName string) int {
	count, _ := s.failureRetries.Get(sbomName)
	count++
	if count >= maxScanRetries {
		s.failureRetries.Remove(sbomName)
	} else {
		s.failureRetries.Add(sbomName, count)
	}
	return count
}

// incrementCrashLoopCount increments the long-TTL, crash-only backstop counter for sbomName and
// returns the new count. Every scanner crash increments this alongside incrementFailureCount, but
// unlike that shared budget, this one never mixes in generic failures and never expires within
// the timescale of a typical restart gap, so a crash loop with sparse cadence still accumulates
// to a pin instead of resetting indefinitely.
func (s *SbomManager) incrementCrashLoopCount(sbomName string) int {
	count, _ := s.crashLoopRetries.Get(sbomName)
	count++
	if count >= maxScanRetries {
		s.crashLoopRetries.Remove(sbomName)
	} else {
		s.crashLoopRetries.Add(sbomName, count)
	}
	return count
}

// handleGenericFailure responds to a non-deterministic SBOM-generation failure (source
// construction, syft cataloging, or sidecar scan error). markSBOMStatus only ever patches
// annotations, never Spec, so it's always safe to call regardless of whether the SBOM
// previously had real content -- but the image is only pinned Incomplete after
// maxScanRetries consecutive failures, so a single transient error doesn't lose coverage.
// The retry budget is shared with handleScannerCrash via incrementFailureCount, so failures
// alternating between generic and scanner-crash categories count against the same budget.
func (s *SbomManager) handleGenericFailure(sbomName string) {
	if s.incrementFailureCount(sbomName) < maxScanRetries {
		return
	}
	s.markSBOMStatus(sbomName, helpersv1.Incomplete, nil)
}

// reportFailure sends a scan failure report to the backend via the failure reporter.
// Fire-and-forget: errors are logged, never propagated. Safe to call with nil reporter.
func (s *SbomManager) reportFailure(notif containercollection.PubSubEvent, imageTag, imageID, reason string, scanErr error) {
	if s.failureReporter == nil {
		return
	}

	report := scanfailure.ScanFailureReport{
		ImageTag:      imageTag,
		ImageHash:     imageID,
		FailureCase:   scanfailure.ScanFailureSBOMGeneration,
		FailureReason: reason,
		Timestamp:     time.Now(),
		Workloads: []scanfailure.WorkloadIdentifier{{
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
