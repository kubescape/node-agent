package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
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
	"github.com/kubescape/node-agent/pkg/sbommanager"
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
)

const (
	digestDelim         = "@"
	NodeNameMetadataKey = "kubescape.io/node-name"
)

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
	storageClient      storage.StorageClient
	version            string
}

var _ sbommanager.SbomManagerClient = (*SbomManager)(nil)

func CreateSbomManager(ctx context.Context, cfg config.Config, socketPath string, storageClient storage.StorageClient, k8sObjectCache objectcache.K8sObjectCache) (*SbomManager, error) {
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
	return &SbomManager{
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
	}, nil
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
	// check if the container should be ignored
	if s.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		return
	}
	// enqueue the container for processing
	s.pool.Submit(func() {
		s.processContainer(notif)
	})
}

func (s *SbomManager) processContainer(notif containercollection.PubSubEvent) {
	sharedData, err := s.waitForSharedContainerData(notif.Container.Runtime.ContainerID)
	if err != nil {
		logger.L().Error("SbomManager - container not found in shared data",
			helpers.String("container ID", notif.Container.Runtime.ContainerID))
		return
	}
	// prepare SBOM name
	sbomName, err := names.ImageInfoToSlug(sharedData.ImageTag, sharedData.ImageID)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to generate SBOM name",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("imageName", sharedData.ImageTag),
			helpers.String("imageDigest", sharedData.ImageID))
		return
	}
	// try to create a SBOM with initializing status to reserve our slot
	imageID := normalizeImageID(sharedData.ImageTag, sharedData.ImageID)
	wipSbom := &v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbomName,
			Annotations: map[string]string{
				helpersv1.ImageIDMetadataKey:     imageID,
				helpersv1.ImageTagMetadataKey:    sharedData.ImageTag,
				helpersv1.StatusMetadataKey:      helpersv1.Initializing,
				NodeNameMetadataKey:              s.cfg.NodeName,
				helpersv1.ToolVersionMetadataKey: s.version,
			},
			Labels: labelsFromImageID(imageID),
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
			logger.L().Debug("SbomManager - image is too large for SBOM processing, skipping",
				helpers.String("namespace", notif.Container.K8s.Namespace),
				helpers.String("pod", notif.Container.K8s.PodName),
				helpers.String("container", notif.Container.K8s.ContainerName),
				helpers.String("sbomName", sbomName),
				helpers.String("nodeName", wipSbom.Annotations[NodeNameMetadataKey]))
			return
		case wipSbom.Annotations[helpersv1.StatusMetadataKey] == helpersv1.Ready:
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
	// get container mounts
	pid := strconv.Itoa(int(notif.Container.ContainerPid()))
	mounts, err := s.getMountedVolumes(pid)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to get mounted volumes",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		return
	}
	// get image layers
	imageStatus, err := s.getImageStatus(notif.Container.Runtime.ContainerImageName) // use original name to ask the CRI
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to get image layers",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		return
	}
	// prepare image source
	src, err := NewSource(sharedData.ImageTag, sharedData.ImageID, imageID, imageStatus, mounts, s.cfg.MaxImageSize)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to create image source",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		if errors.Is(err, ErrImageTooLarge) {
			delete(wipSbom.Annotations, NodeNameMetadataKey)
			wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
			_, _ = s.storageClient.ReplaceSBOM(wipSbom)
		}
		return
	}
	// create the SBOM
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.ToolName = "syft"
	cfg.ToolVersion = s.version
	if s.cfg.EnableEmbeddedSboms {
		// ask Syft to also scan the image for embedded SBOMs
		cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
	}
	syftSBOM, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to generate SBOM",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("sbomName", sbomName))
		// TODO we could save the error in a status field
		return
	}
	// prepare the SBOM
	delete(wipSbom.Annotations, NodeNameMetadataKey)
	wipSbom.Spec.Metadata.Report.CreatedAt = wipSbom.CreationTimestamp
	wipSbom.Spec.Metadata.Tool.Name = "syft"
	wipSbom.Spec.Metadata.Tool.Version = s.version
	wipSbom.Spec.Syft = toSyftDocument(syftSBOM)
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
	} else {
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Ready
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
		return
	}
	logger.L().Debug("SbomManager - saved SBOM after successful processing",
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("sbomName", sbomName))
}

func (s *SbomManager) waitForSharedContainerData(containerID string) (*utils.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*utils.WatchedContainerData, error) {
		if sharedData := s.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

func formatSBOM(s sbom.SBOM) ([]byte, error) {
	bytes, err := format.Encode(s, syftjson.NewFormatEncoder())
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes, nil
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

func toCPEs(c []model.CPE) v1beta1.CPEs {
	cpes := make(v1beta1.CPEs, len(c))
	for i := range c {
		cpes[i] = v1beta1.CPE(c[i])
	}
	return cpes
}

func toDigests(d []file.Digest) []v1beta1.Digest {
	digests := make([]v1beta1.Digest, len(d))
	for i := range d {
		digests[i].Algorithm = d[i].Algorithm
		digests[i].Value = d[i].Value
	}
	return digests
}

func toELFSecurityFeatures(f *file.ELFSecurityFeatures) *v1beta1.ELFSecurityFeatures {
	if f == nil {
		return nil
	}
	return &v1beta1.ELFSecurityFeatures{
		SymbolTableStripped:           f.SymbolTableStripped,
		StackCanary:                   f.StackCanary,
		NoExecutable:                  f.NoExecutable,
		RelocationReadOnly:            v1beta1.RelocationReadOnly(f.RelocationReadOnly),
		PositionIndependentExecutable: f.PositionIndependentExecutable,
		DynamicSharedObject:           f.DynamicSharedObject,
		LlvmSafeStack:                 f.LlvmSafeStack,
		LlvmControlFlowIntegrity:      f.LlvmControlFlowIntegrity,
		ClangFortifySource:            f.ClangFortifySource,
	}
}

func toExecutable(e *file.Executable) *v1beta1.Executable {
	if e == nil {
		return nil
	}
	return &v1beta1.Executable{
		Format:              v1beta1.ExecutableFormat(e.Format),
		HasExports:          e.HasExports,
		HasEntrypoint:       e.HasEntrypoint,
		ImportedLibraries:   e.ImportedLibraries,
		ELFSecurityFeatures: toELFSecurityFeatures(e.ELFSecurityFeatures),
	}
}

func toFileLicenseEvidence(e *model.FileLicenseEvidence) *v1beta1.FileLicenseEvidence {
	if e == nil {
		return nil
	}
	return &v1beta1.FileLicenseEvidence{
		Confidence: int64(e.Confidence),
		Offset:     int64(e.Offset),
		Extent:     int64(e.Extent),
	}
}

func toFileLicenses(l []model.FileLicense) []v1beta1.FileLicense {
	licenses := make([]v1beta1.FileLicense, len(l))
	for i := range l {
		licenses[i].Value = l[i].Value
		licenses[i].SPDXExpression = l[i].SPDXExpression
		licenses[i].Type = v1beta1.LicenseType(l[i].Type)
		licenses[i].Evidence = toFileLicenseEvidence(l[i].Evidence)
	}
	return licenses
}

func toFileMetadataEntry(m *model.FileMetadataEntry) *v1beta1.FileMetadataEntry {
	if m == nil {
		return nil
	}
	return &v1beta1.FileMetadataEntry{
		Mode:            int64(m.Mode),
		Type:            m.Type,
		LinkDestination: m.LinkDestination,
		UserID:          int64(m.UserID),
		GroupID:         int64(m.GroupID),
		MIMEType:        m.MIMEType,
		Size_:           m.Size,
	}
}

func toLicenses(l []model.License) v1beta1.Licenses {
	licenses := make(v1beta1.Licenses, len(l))
	for i := range l {
		licenses[i].Value = l[i].Value
		licenses[i].SPDXExpression = l[i].SPDXExpression
		licenses[i].Type = v1beta1.LicenseType(l[i].Type)
		licenses[i].URLs = l[i].URLs
		licenses[i].Locations = toLocations(l[i].Locations)
	}
	return licenses
}

func toLocations(l []file.Location) []v1beta1.Location {
	locations := make([]v1beta1.Location, len(l))
	for i := range l {
		locations[i].Coordinates = v1beta1.Coordinates(l[i].Coordinates)
		locations[i].VirtualPath = l[i].AccessPath
		locations[i].RealPath = l[i].RealPath
		locations[i].Annotations = l[i].Annotations
	}
	return locations
}

func toSyftDocument(sbomSBOM *sbom.SBOM) v1beta1.SyftDocument {
	doc := syftjson.ToFormatModel(*sbomSBOM, syftjson.EncoderConfig{
		Pretty: false,
		Legacy: false,
	})
	configuration, _ := json.Marshal(doc.Descriptor.Configuration)
	metadata, _ := json.Marshal(doc.Source.Metadata)
	syftDocument := v1beta1.SyftDocument{
		Artifacts:             toSyftPackages(doc.Artifacts),
		ArtifactRelationships: toSyftRelationships(doc.ArtifactRelationships),
		Files:                 make([]v1beta1.SyftFile, len(doc.Files)),
		SyftSource: v1beta1.SyftSource{
			ID:       doc.Source.ID,
			Name:     doc.Source.Name,
			Version:  doc.Source.Version,
			Type:     doc.Source.Type,
			Metadata: metadata,
		},
		Distro: v1beta1.LinuxRelease{
			PrettyName:       doc.Distro.PrettyName,
			Name:             doc.Distro.Name,
			ID:               doc.Distro.ID,
			IDLike:           v1beta1.IDLikes(doc.Distro.IDLike),
			Version:          doc.Distro.Version,
			VersionID:        doc.Distro.VersionID,
			VersionCodename:  doc.Distro.VersionCodename,
			BuildID:          doc.Distro.BuildID,
			ImageID:          doc.Distro.ImageID,
			ImageVersion:     doc.Distro.ImageVersion,
			Variant:          doc.Distro.Variant,
			VariantID:        doc.Distro.VariantID,
			HomeURL:          doc.Distro.HomeURL,
			SupportURL:       doc.Distro.SupportURL,
			BugReportURL:     doc.Distro.BugReportURL,
			PrivacyPolicyURL: doc.Distro.PrivacyPolicyURL,
			CPEName:          doc.Distro.CPEName,
			SupportEnd:       doc.Distro.SupportEnd,
		},
		SyftDescriptor: v1beta1.SyftDescriptor{
			Name:          doc.Descriptor.Name,
			Version:       doc.Descriptor.Version,
			Configuration: configuration,
		},
		Schema: v1beta1.Schema{
			Version: doc.Schema.Version,
			URL:     doc.Schema.URL,
		},
	}
	// convert files
	for i := range doc.Files {
		syftDocument.Files[i].ID = doc.Files[i].ID
		syftDocument.Files[i].Location.RealPath = doc.Files[i].Location.RealPath
		syftDocument.Files[i].Location.FileSystemID = doc.Files[i].Location.FileSystemID
		syftDocument.Files[i].Metadata = toFileMetadataEntry(doc.Files[i].Metadata)
		syftDocument.Files[i].Contents = doc.Files[i].Contents
		syftDocument.Files[i].Digests = toDigests(doc.Files[i].Digests)
		syftDocument.Files[i].Licenses = toFileLicenses(doc.Files[i].Licenses)
		syftDocument.Files[i].Executable = toExecutable(doc.Files[i].Executable)
	}
	return syftDocument
}

func toSyftPackages(p []model.Package) []v1beta1.SyftPackage {
	packages := make([]v1beta1.SyftPackage, len(p))
	for i := range p {
		packages[i].ID = p[i].ID
		packages[i].Name = p[i].Name
		packages[i].Version = p[i].Version
		packages[i].Type = string(p[i].Type)
		packages[i].FoundBy = p[i].FoundBy
		packages[i].Locations = toLocations(p[i].Locations)
		packages[i].Licenses = toLicenses(p[i].Licenses)
		packages[i].Language = string(p[i].Language)
		packages[i].CPEs = toCPEs(p[i].CPEs)
		packages[i].PURL = p[i].PURL
		packages[i].Metadata, _ = json.Marshal(p[i].Metadata)
		packages[i].MetadataType = p[i].MetadataType
	}
	return packages
}

func toSyftRelationships(r []model.Relationship) []v1beta1.SyftRelationship {
	relationships := make([]v1beta1.SyftRelationship, len(r))
	for i := range r {
		relationships[i].Parent = r[i].Parent
		relationships[i].Child = r[i].Child
		relationships[i].Type = r[i].Type
	}
	return relationships
}
