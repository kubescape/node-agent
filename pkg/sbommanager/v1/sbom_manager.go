package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	securejoin "github.com/cyphar/filepath-securejoin"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sbommanager"
	"github.com/moby/sys/mountinfo"
	imagedigest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/afero"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type SbomManager struct {
	appFs              afero.Fs
	cfg                config.Config
	ctx                context.Context
	imageServiceClient runtime.ImageServiceClient
	procDir            string
	version            string
}

var _ sbommanager.SbomManagerClient = (*SbomManager)(nil)

func CreateSbomManager(ctx context.Context, cfg config.Config, socketPath string) (*SbomManager, error) {
	procDir, err := getProcDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get proc dir: %w", err)
	}
	logger.L().Info("SbomManager creating", helpers.String("socketPath", socketPath))
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
		imageServiceClient: runtime.NewImageServiceClient(conn),
		procDir:            procDir,
		version:            packageVersion("github.com/anchore/syft"),
	}, nil
}

type imageInfo struct {
	ImageSpec imagespec.Image `json:"imageSpec"`
}

func (s *SbomManager) getImageLayers(imageID string) ([]imagedigest.Digest, error) {
	status, err := s.imageServiceClient.ImageStatus(context.Background(), &runtime.ImageStatusRequest{
		Image:   &runtime.ImageSpec{Image: imageID},
		Verbose: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get image status: %w", err)
	}
	var info imageInfo
	err = json.Unmarshal([]byte(status.Info["info"]), &info)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal image info: %w", err)
	}
	return info.ImageSpec.RootFS.DiffIDs, nil
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
			return strings.Split(option[9:], ":"), nil
		}
	}
	return nil, fmt.Errorf("failed to find lowerdir in %s", mounts[0].VFSOptions)
}

func getProcDir() (string, error) {
	// read HOST_ROOT from env
	hostRoot, exists := os.LookupEnv("HOST_ROOT")
	if !exists {
		hostRoot = "/host"
	}
	// use securejoin to join the two, add proc and store in procDir
	procDir, err := securejoin.SecureJoin(hostRoot, "/proc")
	if err != nil {
		return "", fmt.Errorf("failed to join /proc dir: %w", err)
	}
	return procDir, nil
}

func (s *SbomManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// check if the container should be ignored
	if s.cfg.SkipNamespace(notif.Container.K8s.Namespace) {
		return
	}
	// prepare container info
	pid := strconv.Itoa(int(notif.Container.Pid))
	rootFS := filepath.Join(s.procDir, pid, "root")
	mounts, err := s.getMountedVolumes(pid)
	if err != nil {
		logger.L().Error("Failed to get mounted volumes",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("pid", pid))
		return
	}
	logger.L().Debug("SbomManager got mounted volumes",
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("pid", pid),
		helpers.String("rootFS", rootFS),
		helpers.String("mounts", strings.Join(mounts, ", ")))
	// prepare image info
	imageName := notif.Container.Runtime.ContainerImageName
	layers, err := s.getImageLayers(imageName)
	if err != nil {
		logger.L().Error("Failed to get image layers",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("pid", pid))
		return
	}
	logger.L().Debug("SbomManager got image layers",
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("pid", pid),
		helpers.String("rootFS", rootFS),
		helpers.Interface("layers", layers))
	// create the SBOM
	logger.L().Debug("generating SBOM",
		helpers.String("imageName", imageName))
	// FIXME: seem to pull image
	src, err := syft.GetSource(context.Background(), imageName, syft.DefaultGetSourceConfig().WithBasePath(rootFS))
	if err != nil {
		logger.L().Error("Failed to get source",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("pid", pid))
		return
	}
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.ToolName = "syft"
	cfg.ToolVersion = s.version
	syftSBOM, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		logger.L().Error("Failed to generate SBOM",
			helpers.Error(err),
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("pod", notif.Container.K8s.PodName),
			helpers.String("container", notif.Container.K8s.ContainerName),
			helpers.String("pid", pid))
		return
	}
	logger.L().Info("SbomManager got SBOM",
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("pod", notif.Container.K8s.PodName),
		helpers.String("container", notif.Container.K8s.ContainerName),
		helpers.String("pid", pid),
		helpers.Interface("sbom", syftSBOM))
	// match package names with image layers
	//packages := syftSBOM.Artifacts
	//var j int
	//for pi, pkg := range packages {
	//	// go over the location of files in the package
	//	var layerID imagedigest.Digest
	//	for li, location := range pkg.Locations {
	//		if layerID == "" {
	//			// check if the location is in the mounted volumes
	//			pathToFile := filepath.Join()
	//		} else {
	//			break
	//		}
	//	}
	//	if layerID != "" {
	//
	//	}
	//	packages[pi] = pkg
	//}
	// TODO send the SBOM to the server
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
