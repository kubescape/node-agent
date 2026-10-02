package v1

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/source"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func writeMountInfo(t *testing.T, hostRoot, options string) *SbomManager {
	t.Helper()
	procDir := filepath.Join(hostRoot, "proc")
	require.NoError(t, os.MkdirAll(filepath.Join(procDir, "123"), 0o755))
	info := fmt.Sprintf("36 25 0:32 / / rw,relatime - overlay overlay %s\n", options)
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "123", "mountinfo"), []byte(info), 0o644))
	return &SbomManager{appFs: afero.NewOsFs(), hostRoot: hostRoot, procDir: procDir}
}

// Exercise mount discovery through real Syft cataloging and the manager's
// completed SBOM write, with both the in-process and gRPC scanner paths.
func TestGetMountedVolumesRelativeLayersScanLifecycle(t *testing.T) {
	for _, sidecar := range []bool{false, true} {
		t.Run(fmt.Sprintf("sidecar=%t", sidecar), func(t *testing.T) {
			hostRoot := t.TempDir()
			snapshots := "/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"
			for path, content := range map[string]string{
				"11/fs/etc/os-release":       "ID=alpine\nVERSION_ID=3.21.0\n",
				"12/fs/lib/apk/db/installed": "P:issue-1004-package\nV:1.2.3-r0\nA:x86_64\nL:MIT\nT:regression fixture\n\n",
				"13/fs/lib/apk/db/installed": "P:writable-container-package\nV:9.9.9-r0\nA:x86_64\nL:MIT\n\n",
			} {
				path = filepath.Join(hostRoot, snapshots, path)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
			}
			mountManager := writeMountInfo(t, hostRoot, "rw,lowerdir=12/fs:11/fs,upperdir="+snapshots+"/13/fs,workdir="+snapshots+"/13/work")
			mounts, err := mountManager.getMountedVolumes("123")
			require.NoError(t, err)
			notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
			imageStatus.Info = map[string]string{"info": `{"imageSpec":{"rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]},"architecture":"amd64","os":"linux"}}`}
			stored := newFakeSbomClient()
			manager := newTestManagerInProcess(stored, "test-syft-version", 1024*1024)
			manager.cfg.MaxSBOMSize = 10 * 1024 * 1024
			manager.metrics = metricsmanager.NewMetricsNoop()
			if sidecar {
				socket := filepath.Join(t.TempDir(), "scanner.sock")
				listener, err := net.Listen("unix", socket)
				require.NoError(t, err)
				server := grpc.NewServer()
				pb.RegisterSBOMScannerServer(server, sbomscanner.NewScannerServer())
				go server.Serve(listener)
				t.Cleanup(server.Stop)
				manager.scannerClient, err = sbomscanner.NewSBOMScannerClient(socket)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, manager.scannerClient.Close()) })
			}
			manager.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)
			sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
			require.NoError(t, err)
			result := stored.get(sbomName)
			require.Equal(t, helpersv1.Learning, result.Annotations[helpersv1.StatusMetadataKey], "SBOM must leave initializing after a successful local scan")
			require.NotEmpty(t, result.Spec.Metadata.Tool.Version)
			require.Len(t, result.Spec.Syft.Artifacts, 1, "only image layers, not the writable container layer, should be scanned")
			require.Equal(t, "issue-1004-package", result.Spec.Syft.Artifacts[0].Name)
			require.Equal(t, "1.2.3-r0", result.Spec.Syft.Artifacts[0].Version)
		})
	}
}

func TestGetMountedVolumesK3sRelativeLayers(t *testing.T) {
	hostRoot := t.TempDir()
	snapshots := "/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"
	want := []string{filepath.Join(hostRoot, snapshots, "9875/fs"), filepath.Join(hostRoot, snapshots, "9874/fs")}
	for _, layer := range want {
		require.NoError(t, os.MkdirAll(layer, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(layer, "test.txt"), []byte("image layer"), 0o644))
	}
	s := writeMountInfo(t, hostRoot, "rw,lowerdir=9875/fs:9874/fs,upperdir="+snapshots+"/9876/fs,workdir="+snapshots+"/9876/work")
	mounts, err := s.getMountedVolumes("123")
	require.NoError(t, err)
	_, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	imageStatus.Info = map[string]string{"info": `{"imageSpec":{"rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}}}`}
	src, err := syftutil.NewSource(imageTag, imageID, imageID, imageStatus, mounts, 1024*1024)
	require.NoError(t, err)
	_, err = src.FileResolver(source.SquashedScope)
	require.NoError(t, err, "the scanner must be able to open the actual k3s layers")
	require.Equal(t, want, mounts)
}

func TestGetMountedVolumes(t *testing.T) {
	const snapshotter = "/io.containerd.snapshotter.v1.overlayfs/snapshots"
	for _, root := range []string{"/var/lib/containerd", "/var/lib/rancher/k3s/agent/containerd", "/var/lib/rancher/rke2/agent/containerd", "/custom/containerd"} {
		t.Run(root, func(t *testing.T) {
			snapshots := root + snapshotter
			for _, options := range []string{
				"rw,lowerdir=12/fs:11/fs,upperdir=" + snapshots + "/13/fs,workdir=" + snapshots + "/13/work",
				"rw,upperdir=" + snapshots + "/13/fs,lowerdir=12/fs:11/fs",
				"rw,lowerdir=12/fs:11/fs,workdir=" + snapshots + "/13/work",
				"rw,upperdir=13/fs,lowerdir=12/fs:11/fs,workdir=" + snapshots + "/13/work",
				"rw,lowerdir=" + snapshots + "/12/fs:11/fs,upperdir=" + snapshots + "/13/fs",
			} {
				s := writeMountInfo(t, t.TempDir(), options)
				mounts, err := s.getMountedVolumes("123")
				require.NoError(t, err, options)
				require.Equal(t, []string{filepath.Join(s.hostRoot, snapshots, "12/fs"), filepath.Join(s.hostRoot, snapshots, "11/fs")}, mounts)
			}
		})
	}
	t.Run("absolute lowerdirs need no upperdir", func(t *testing.T) {
		s := writeMountInfo(t, t.TempDir(), "ro,lowerdir=/custom/layer2:/custom/layer1")
		mounts, err := s.getMountedVolumes("123")
		require.NoError(t, err)
		require.Equal(t, []string{filepath.Join(s.hostRoot, "custom/layer2"), filepath.Join(s.hostRoot, "custom/layer1")}, mounts)
	})
	for _, options := range []string{
		"rw,lowerdir=12/fs:11/fs",
		"rw,lowerdir=12/fs:11/fs,upperdir=13/fs,workdir=13/work",
		"rw,lowerdir=12/fs:11/fs,upperdir=/unrelated/upper,workdir=/unrelated/work",
	} {
		t.Run(options, func(t *testing.T) {
			s := writeMountInfo(t, t.TempDir(), options)
			mounts, err := s.getMountedVolumes("123")
			require.ErrorContains(t, err, "relative lowerdir")
			require.Nil(t, mounts, "do not guess a root when the mount provides no absolute snapshot path")
		})
	}
	t.Run("missing lowerdir", func(t *testing.T) {
		s := writeMountInfo(t, t.TempDir(), "rw,upperdir=/custom/snapshots/13/fs")
		_, err := s.getMountedVolumes("123")
		require.ErrorContains(t, err, "failed to find lowerdir")
	})
	t.Run("non-overlay snapshotter", func(t *testing.T) {
		s := writeMountInfo(t, t.TempDir(), "rw")
		require.NoError(t, os.WriteFile(filepath.Join(s.procDir, "123", "mountinfo"), []byte("36 25 0:32 / / rw - btrfs /dev/sda rw\n"), 0o644))
		mounts, err := s.getMountedVolumes("123")
		require.NoError(t, err)
		require.Equal(t, []string{filepath.Join(s.procDir, "123", "root")}, mounts)
	})
	t.Run("missing mountinfo", func(t *testing.T) {
		s := &SbomManager{appFs: afero.NewOsFs(), procDir: t.TempDir()}
		_, err := s.getMountedVolumes("123")
		require.ErrorContains(t, err, "failed to open /proc/123/mountinfo")
	})
}
