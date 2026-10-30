package igbackend

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"path"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	imageidentity "github.com/opencontainers/image-spec/identity"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This evidence comes from an admin-configured trusted runtime, never policy
// input or annotations. A fake source exists only for bounded validation tests.
type imageEvidenceSource interface {
	Evidence(context.Context, string) (containerdImageEvidence, error)
}
type containerdImageEvidence struct {
	Namespace, ID, Image, Snapshotter, SnapshotKey string
	RuntimeName                                    string
	SandboxID, PodUID, PodNamespace                string
	PID                                            uint32
	Running                                        bool
	Spec                                           *specs.Spec
	SandboxSpec                                    *specs.Spec // authenticated CRI sandbox OCI spec, not annotations
	DiffIDs                                        []digest.Digest
	Active                                         snapshots.Info
	Parents                                        []snapshots.Info // nearest committed parent first
	Mounts                                         []mount.Mount
}
type containerdImageSource struct{ client *containerd.Client }

// The admin must authenticate and protect the socket and its parent directory.
// This does not discover sockets from workloads. Close belongs to the creator;
// image leases borrow the source and never close a shared client.
func newContainerdImageSource(socket string) (*containerdImageSource, error) {
	if !simpleEvidencePath(socket) {
		return nil, fmt.Errorf("containerd requires a canonical admin-configured Unix socket")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, socket, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	e := unix.Fstat(fd, &stat)
	ce := unix.Close(fd)
	if e != nil || ce != nil {
		return nil, errors.Join(e, ce)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, fmt.Errorf("containerd endpoint is not a Unix socket")
	}
	client, err := containerd.New(socket, containerd.WithDefaultNamespace("k8s.io"), containerd.WithTimeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	return &containerdImageSource{client: client}, nil
}
func (s *containerdImageSource) Close() error { return s.client.Close() }
func (s *containerdImageSource) Evidence(ctx context.Context, id string) (containerdImageEvidence, error) {
	ctx, finish := newEvidenceContext(ctx)
	defer finish()
	var result containerdImageEvidence
	if !fullContainerID(id) {
		return result, fmt.Errorf("exact 64-character containerd container ID required")
	}
	ctx = namespaces.WithNamespace(ctx, "k8s.io")
	container, err := s.client.LoadContainer(ctx, id)
	if err != nil {
		return result, err
	}
	info, err := container.Info(ctx)
	if err != nil {
		return result, err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return result, err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return result, err
	}
	spec, err := boundedContainerSpec(ctx, container)
	if err != nil {
		return result, err
	}
	image, err := container.Image(ctx)
	if err != nil {
		return result, err
	}
	diffs, err := boundedImageRootFS(ctx, image)
	if err != nil {
		return result, err
	}
	if len(diffs) == 0 || len(diffs) > 128 {
		return result, fmt.Errorf("unsupported image layer count")
	}
	if info.Snapshotter != "overlayfs" {
		return result, fmt.Errorf("only containerd overlayfs snapshotter is supported")
	}
	service := s.client.SnapshotService(info.Snapshotter)
	active, err := service.Stat(ctx, info.SnapshotKey)
	if err != nil {
		return result, err
	}
	mounts, err := service.Mounts(ctx, info.SnapshotKey)
	if err != nil {
		return result, err
	}
	result = containerdImageEvidence{Namespace: "k8s.io", ID: info.ID, Image: info.Image, RuntimeName: info.Runtime.Name, Snapshotter: info.Snapshotter, SnapshotKey: info.SnapshotKey, PID: task.Pid(), Running: status.Status == containerd.Running, Spec: spec, DiffIDs: diffs, Active: active, Mounts: mounts}
	if info.Labels["io.cri-containerd.kind"] == "container" {
		extension := info.Extensions["io.cri-containerd.container.metadata"]
		if extension == nil {
			return containerdImageEvidence{}, fmt.Errorf("missing authenticated CRI container metadata")
		}
		sandboxID, e := criContainerSandbox(extension.GetValue(), info.ID)
		if e != nil {
			return containerdImageEvidence{}, e
		}
		sandbox, e := s.client.LoadContainer(ctx, sandboxID)
		if e != nil {
			return containerdImageEvidence{}, e
		}
		sandboxInfo, e := sandbox.Info(ctx)
		if e != nil {
			return containerdImageEvidence{}, e
		}
		sandboxExtension := sandboxInfo.Extensions["io.cri-containerd.sandbox.metadata"]
		if sandboxInfo.ID != sandboxID || sandboxInfo.Labels["io.cri-containerd.kind"] != "sandbox" || sandboxExtension == nil {
			return containerdImageEvidence{}, fmt.Errorf("CRI sandbox identity is not authenticated")
		}
		uid, namespace, e := criSandboxIdentity(sandboxExtension.GetValue(), sandboxID)
		if e != nil {
			return containerdImageEvidence{}, e
		}
		sandboxSpec, e := boundedContainerSpec(ctx, sandbox)
		if e != nil {
			return containerdImageEvidence{}, e
		}
		// Bound runtime metadata before retaining it in the evidence snapshot.
		rawSandboxSpec, e := json.Marshal(sandboxSpec)
		if e != nil {
			return containerdImageEvidence{}, e
		}
		if len(rawSandboxSpec) > 1<<20 {
			return containerdImageEvidence{}, fmt.Errorf("CRI sandbox spec budget exceeded")
		}
		result.SandboxSpec = sandboxSpec
		result.SandboxID = sandboxID
		result.PodUID = uid
		result.PodNamespace = namespace
	} else if spec.Annotations["io.kubernetes.cri.sandbox-id"] != "" {
		return containerdImageEvidence{}, fmt.Errorf("CRI annotation without authenticated runtime metadata")
	}
	parent := active.Parent
	for parent != "" {
		if err := ctx.Err(); err != nil {
			return containerdImageEvidence{}, err
		}
		if len(result.Parents) >= 128 {
			return containerdImageEvidence{}, fmt.Errorf("snapshot ancestry budget exceeded")
		}
		item, err := service.Stat(ctx, parent)
		if err != nil {
			return containerdImageEvidence{}, err
		}
		result.Parents = append(result.Parents, item)
		parent = item.Parent
	}
	return result, nil
}

// Decode the runtime-owned versioned extensions, not workload annotations.
func criContainerSandbox(raw []byte, id string) (string, error) {
	var value struct {
		Version  string
		Metadata struct{ ID, SandboxID string }
	}
	if len(raw) > 1<<20 {
		return "", fmt.Errorf("CRI metadata budget exceeded")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	if value.Version != "v1" || value.Metadata.ID != id || !fullContainerID(value.Metadata.SandboxID) {
		return "", fmt.Errorf("CRI container/sandbox metadata mismatch")
	}
	return value.Metadata.SandboxID, nil
}
func criSandboxIdentity(raw []byte, id string) (string, string, error) {
	var value struct {
		Version  string
		Metadata struct {
			ID     string
			Config struct {
				Metadata struct{ UID, Namespace string }
			}
		}
	}
	if len(raw) > 1<<20 {
		return "", "", fmt.Errorf("CRI metadata budget exceeded")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", "", err
	}
	metadata := value.Metadata.Config.Metadata
	if value.Version != "v1" || value.Metadata.ID != id || metadata.UID == "" || metadata.Namespace == "" {
		return "", "", fmt.Errorf("CRI sandbox pod identity mismatch")
	}
	return metadata.UID, metadata.Namespace, nil
}
func validatedSandboxFile(e containerdImageEvidence, m specs.Mount, lower []lowerLayer) bool {
	if !fullContainerID(e.SandboxID) || len(lower) == 0 {
		return false
	}
	filename := path.Base(m.Source)
	if filename != "hosts" && filename != "hostname" && filename != "resolv.conf" {
		return false
	}
	if m.Destination != "/etc/"+filename {
		return false
	}
	const marker = "/io.containerd.snapshotter.v1.overlayfs/snapshots/"
	runtimeRoot := ""
	for _, layer := range lower {
		root, suffix, ok := strings.Cut(layer.name, marker)
		parts := strings.Split(suffix, "/")
		if !ok || !simpleEvidencePath(root) || len(parts) != 2 || parts[1] != "fs" {
			return false
		}
		if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil {
			return false
		}
		if runtimeRoot != "" && runtimeRoot != root {
			return false
		}
		runtimeRoot = root
	}
	return m.Source == path.Join(runtimeRoot, "io.containerd.grpc.v1.cri", "sandboxes", e.SandboxID, filename)
}

// validatedSandboxShm authenticates only the CRI sandbox's ordinary shared-memory
// mount. It is not a helper exemption and does not establish physical safety:
// validateSandboxShmPins must additionally prove a restricted tmpfs root, and the
// normal bounded volume scan still applies. The runtime's StateDir may differ
// from its persistent RootDir; never infer one by rewriting a pathname.
func validatedSandboxShm(e containerdImageEvidence, m specs.Mount) bool {
	if !fullContainerID(e.SandboxID) || e.PodUID == "" || e.PodNamespace == "" || e.SandboxSpec == nil || e.SandboxSpec.Linux == nil || len(e.SandboxSpec.Mounts) > 128 {
		return false
	}
	if m.Type != "bind" || m.Destination != "/dev/shm" || !simpleEvidencePath(m.Source) || !strings.HasSuffix(m.Source, "/sandboxes/"+e.SandboxID+"/shm") || !validBindOptions(m.Options) || (!containsEvidence(m.Options, "bind") && !containsEvidence(m.Options, "rbind")) {
		return false
	}
	// A host IPC namespace is not an authenticated sandbox-owned tmpfs.
	isolatedIPC, isolatedMount := false, false
	for _, ns := range e.SandboxSpec.Linux.Namespaces {
		switch ns.Type {
		case specs.IPCNamespace:
			if isolatedIPC || ns.Path != "" {
				return false
			}
			isolatedIPC = true
		case specs.MountNamespace:
			if isolatedMount || ns.Path != "" {
				return false
			}
			isolatedMount = true
		}
	}
	if !isolatedIPC || !isolatedMount {
		return false
	}
	found := false
	for _, sandboxMount := range e.SandboxSpec.Mounts {
		if sandboxMount.Destination != "/dev/shm" {
			continue
		}
		if found || sandboxMount.Type != "bind" || sandboxMount.Source != m.Source || !validBindOptions(sandboxMount.Options) || (!containsEvidence(sandboxMount.Options, "bind") && !containsEvidence(sandboxMount.Options, "rbind")) {
			return false
		}
		for _, option := range []string{"ro", "nosuid", "nodev", "noexec"} {
			if !containsEvidence(sandboxMount.Options, option) {
				return false
			}
		}
		found = true
	}
	return found
}

func readSelfMountInfo() ([]byte, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("self mountinfo budget exceeded")
	}
	return data, nil
}
func validateSandboxShmPins(source, destination *os.File, sourceMounts, destinationMounts []byte, evidence containerdImageEvidence, process *linuxLease) error {
	for position, pin := range []struct {
		file   *os.File
		mounts []byte
	}{{source, sourceMounts}, {destination, destinationMounts}} {
		var fs unix.Statfs_t
		if err := unix.Fstatfs(int(pin.file.Fd()), &fs); err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(pin.file.Fd()), &stat); err != nil {
			return err
		}
		var sx unix.Statx_t
		if err := unix.Statx(int(pin.file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx); err != nil {
			return err
		}
		if sx.Mask&unix.STATX_MNT_ID == 0 {
			return fmt.Errorf("sandbox shm mount identity unavailable")
		}
		if err := validateSandboxShmFacts(fs, stat.Mode, pin.mounts, sx.Mnt_id); err != nil {
			// Containerd/runc may clear inherited destination bind flags. Do not
			// weaken source tmpfs proof, and never waive destination flags from
			// caller-supplied booleans or annotations: re-read the pinned process.
			if position == 0 || process == nil || evidence.RuntimeName != "io.containerd.runc.v2" {
				return err
			}
			status, readErr := process.read("status")
			if readErr != nil {
				return readErr
			}
			if fallbackErr := validateSandboxShmDestinationFacts(fs, stat.Mode, pin.mounts, sx.Mnt_id, evidence.Spec, status); fallbackErr != nil {
				return fallbackErr
			}
		}
	}
	return nil
}
func validateSandboxShmFacts(fs unix.Statfs_t, mode uint32, mountinfo []byte, id uint64) error {
	requiredFlags := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.TMPFS_MAGIC || fs.Flags&requiredFlags != requiredFlags {
		return fmt.Errorf("sandbox shm must be a nosuid/nodev/noexec tmpfs directory")
	}
	return validateRestrictedMountInfo(mountinfo, id, "tmpfs", true, []string{"nosuid", "nodev", "noexec"})
}

// This compatibility matrix is deliberately narrower than ordinary root
// admission. No-new-privileges plus empty capabilities prevent set-ID/file-cap
// privilege acquisition on a destination bind that lost nosuid. The exact OCI
// baseline device rule admits only the trusted runc default safe-device rules;
// it is NOT a claim that effective device access is literally deny-all. Runtime
// and current cgroup authority are the same trusted prerequisites as seccomp.
func validateSandboxShmUnprivileged(spec *specs.Spec, status []byte) error {
	if spec == nil || spec.Process == nil || !spec.Process.NoNewPrivileges || spec.Process.Capabilities == nil || spec.Linux == nil || spec.Linux.Resources == nil {
		return fmt.Errorf("sandbox shm destination requires explicit unprivileged runtime evidence")
	}
	caps := spec.Process.Capabilities
	for _, set := range [][]string{caps.Bounding, caps.Effective, caps.Permitted, caps.Inheritable, caps.Ambient} {
		if len(set) != 0 {
			return fmt.Errorf("sandbox shm destination requires empty OCI capability sets")
		}
	}
	devices := spec.Linux.Resources.Devices
	if len(devices) != 1 {
		return fmt.Errorf("sandbox shm destination requires the exact baseline OCI device policy")
	}
	rule := devices[0]
	if rule.Allow || (rule.Type != "" && rule.Type != "a") || rule.Major != nil || rule.Minor != nil || rule.Access != "rwm" {
		return fmt.Errorf("sandbox shm destination has an unsupported OCI device policy")
	}
	if len(status) > 65536 {
		return fmt.Errorf("sandbox shm process status budget exceeded")
	}
	required := map[string]bool{"CapBnd:": false, "CapEff:": false, "CapPrm:": false, "CapInh:": false, "CapAmb:": false, "NoNewPrivs:": false, "Seccomp:": false}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		seen, wanted := required[fields[0]]
		if !wanted {
			continue
		}
		if seen || len(fields) != 2 {
			return fmt.Errorf("ambiguous sandbox shm process status")
		}
		required[fields[0]] = true
		switch fields[0] {
		case "NoNewPrivs:":
			if fields[1] != "1" {
				return fmt.Errorf("sandbox shm destination requires live no-new-privileges")
			}
		case "Seccomp:":
			if fields[1] != "2" {
				return fmt.Errorf("sandbox shm destination requires live seccomp filter")
			}
		default:
			value, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return err
			}
			if value != 0 {
				return fmt.Errorf("sandbox shm destination requires empty live capability sets")
			}
		}
	}
	for _, present := range required {
		if !present {
			return fmt.Errorf("incomplete sandbox shm process status")
		}
	}
	return nil
}
func validateSandboxShmDestinationFacts(fs unix.Statfs_t, mode uint32, mountinfo []byte, id uint64, spec *specs.Spec, status []byte) error {
	if err := validateSandboxShmUnprivileged(spec, status); err != nil {
		return err
	}
	if mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.TMPFS_MAGIC {
		return fmt.Errorf("sandbox shm destination must remain a tmpfs directory")
	}
	return validateRestrictedMountInfo(mountinfo, id, "tmpfs", true, nil)
}

// Mountinfo binds the fstatfs facts to the actual pinned mount. A read-only
// cgroup2 subtree is supported; sandbox shm must be the whole tmpfs root.
func validateRestrictedMountInfo(mountinfo []byte, id uint64, filesystem string, requireRoot bool, requiredOptions []string) error {
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(mountinfo)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return fmt.Errorf("malformed restricted mountinfo")
		}
		mountID, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return err
		}
		if mountID != id {
			continue
		}
		if found || (requireRoot && fields[3] != "/") {
			return fmt.Errorf("%s mount must have an unambiguous supported root", filesystem)
		}
		found = true
		for _, option := range requiredOptions {
			if !containsEvidence(strings.Split(fields[5], ","), option) {
				return fmt.Errorf("%s mount lacks %s", filesystem, option)
			}
		}
		separator := 6
		for separator < len(fields) && fields[separator] != "-" {
			separator++
		}
		if separator+3 >= len(fields) || fields[separator+1] != filesystem {
			return fmt.Errorf("mount is not %s", filesystem)
		}
	}
	if !found {
		return fmt.Errorf("%s mount not found", filesystem)
	}
	return nil
}

func validCgroupMount(m specs.Mount) bool {
	if m.Type != "cgroup" || m.Source != "cgroup" || m.Destination != "/sys/fs/cgroup" || len(m.Options) > 5 {
		return false
	}
	seen := map[string]bool{}
	for _, option := range m.Options {
		if seen[option] {
			return false
		}
		seen[option] = true
		switch option {
		case "ro", "nosuid", "nodev", "noexec", "relatime":
		default:
			return false
		}
	}
	return seen["ro"] && seen["nosuid"] && seen["nodev"] && seen["noexec"]
}
func validateCgroupMountFacts(fs unix.Statfs_t, mode uint32, mountinfo []byte, id uint64) error {
	required := int64(unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.CGROUP2_SUPER_MAGIC || fs.Flags&required != required {
		return fmt.Errorf("cgroup mount must be a read-only nosuid/nodev/noexec cgroup2 directory")
	}
	return validateRestrictedMountInfo(mountinfo, id, "cgroup2", false, []string{"ro", "nosuid", "nodev", "noexec"})
}
func validateCgroupMounts(spec *specs.Spec, root *os.File, mountinfo []byte) error {
	for _, m := range spec.Mounts {
		if m.Type != "cgroup" {
			continue
		}
		if !validCgroupMount(m) {
			return fmt.Errorf("unsupported OCI cgroup mount")
		}
		fd, err := unix.Openat2(int(root.Fd()), m.Destination, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), m.Destination)
		check := func() error {
			var fs unix.Statfs_t
			if err := unix.Fstatfs(fd, &fs); err != nil {
				return err
			}
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); err != nil {
				return err
			}
			var sx unix.Statx_t
			if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx); err != nil {
				return err
			}
			if sx.Mask&unix.STATX_MNT_ID == 0 {
				return fmt.Errorf("cgroup mount identity unavailable")
			}
			return validateCgroupMountFacts(fs, stat.Mode, mountinfo, sx.Mnt_id)
		}
		if err := errors.Join(check(), file.Close()); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidencePodIdentity(e containerdImageEvidence, process *linuxLease) error {
	if process.identity.Namespace != "" && e.PodNamespace != process.identity.Namespace {
		return fmt.Errorf("runtime pod namespace does not match binding")
	}
	if process.identity.PodUID != "" && e.PodUID != string(process.identity.PodUID) {
		return fmt.Errorf("runtime pod UID does not match binding")
	}
	return nil
}

func fullContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func simpleEvidencePath(p string) bool {
	return p != "/" && path.IsAbs(p) && path.Clean(p) == p && len(p) <= 4096 && !strings.ContainsAny(p, "\\,:%\x00\t\r\n ")
}

type overlayEvidence struct {
	Lower       []string
	Upper, Work string
}

func parseOverlayEvidence(options []string) (overlayEvidence, error) {
	var result overlayEvidence
	if len(options) > 32 {
		return result, fmt.Errorf("overlay option budget exceeded")
	}
	seen := map[string]bool{}
	for _, option := range options {
		key, value, hasValue := strings.Cut(option, "=")
		if seen[key] {
			return result, fmt.Errorf("duplicate overlay option %q", key)
		}
		seen[key] = true
		switch key {
		case "lowerdir":
			if !hasValue {
				return result, fmt.Errorf("missing lowerdir")
			}
			result.Lower = strings.Split(value, ":")
			if len(result.Lower) == 0 || len(result.Lower) > 128 {
				return result, fmt.Errorf("lowerdir budget exceeded")
			}
			for _, p := range result.Lower {
				if !simpleEvidencePath(p) {
					return result, fmt.Errorf("unsupported encoded/relative/data-only lowerdir")
				}
			}
		case "upperdir", "workdir":
			if !hasValue || !simpleEvidencePath(value) {
				return result, fmt.Errorf("invalid %s", key)
			}
			if key == "upperdir" {
				result.Upper = value
			} else {
				result.Work = value
			}
		case "rw", "relatime", "nosuid", "nodev", "noexec":
			if hasValue {
				return result, fmt.Errorf("invalid overlay flag")
			}
		case "index", "redirect_dir", "xino":
			if value != "off" {
				return result, fmt.Errorf("unsupported overlay %s", option)
			}
		case "uuid":
			if value != "on" {
				return result, fmt.Errorf("unsupported overlay uuid option")
			}
		case "metacopy":
			if value != "on" && value != "off" {
				return result, fmt.Errorf("unsupported overlay metacopy")
			}
		default:
			return result, fmt.Errorf("unsupported overlay option %q", option)
		}
	}
	if len(result.Lower) == 0 || result.Upper == "" || result.Work == "" {
		return result, fmt.Errorf("active overlay requires lower/upper/work directories")
	}
	all := append(append([]string{}, result.Lower...), result.Upper, result.Work)
	for i, a := range all {
		for _, b := range all[:i] {
			if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
				return result, fmt.Errorf("overlapping overlay directories")
			}
		}
	}
	return result, nil
}
func validateImageSpec(spec *specs.Spec) error {
	if spec == nil || spec.Process == nil || spec.Process.Capabilities == nil || spec.Linux == nil || spec.Root == nil || spec.Root.Path == "" {
		return fmt.Errorf("incomplete OCI isolation evidence")
	}
	if spec.Root.Path != "rootfs" && !simpleEvidencePath(spec.Root.Path) {
		return fmt.Errorf("unsupported OCI root path")
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	if len(encoded) > 1<<20 {
		return fmt.Errorf("OCI spec evidence budget exceeded")
	}
	allowedCaps := map[string]bool{}
	for _, name := range []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP"} {
		allowedCaps[name] = true
	}
	if err := validateRootSeccomp(spec.Linux.Seccomp); err != nil {
		return err
	}
	caps := spec.Process.Capabilities
	for _, set := range [][]string{caps.Bounding, caps.Effective, caps.Permitted, caps.Inheritable, caps.Ambient} {
		if len(set) > 64 {
			return fmt.Errorf("OCI capability budget exceeded")
		}
		for _, cap := range set {
			if !allowedCaps[cap] {
				return fmt.Errorf("unsupported OCI capability %s", cap)
			}
		}
	}
	ns := map[specs.LinuxNamespaceType]bool{}
	for _, item := range spec.Linux.Namespaces {
		if ns[item.Type] {
			return fmt.Errorf("duplicate OCI namespace")
		}
		ns[item.Type] = true
		if (item.Type == specs.MountNamespace || item.Type == specs.PIDNamespace) && item.Path != "" {
			return fmt.Errorf("shared/host mount or PID namespace is unsupported")
		}
	}
	if !ns[specs.MountNamespace] || !ns[specs.PIDNamespace] {
		return fmt.Errorf("isolated mount and PID namespaces required")
	}
	if len(spec.Mounts) > 128 || len(spec.Linux.Devices) > 32 {
		return fmt.Errorf("OCI mount/device budget exceeded")
	}
	destinations := map[string]bool{}
	for _, m := range spec.Mounts {
		if !simpleEvidencePath(m.Destination) || destinations[m.Destination] {
			return fmt.Errorf("invalid OCI mount destination")
		}
		destinations[m.Destination] = true
		// Bind volume provenance is validated against pinned host/process roots below.
		allowed := false
		switch m.Type {
		case "bind":
			allowed = simpleEvidencePath(m.Source) && (containsEvidence(m.Options, "bind") || containsEvidence(m.Options, "rbind"))
			if !validBindOptions(m.Options) {
				return fmt.Errorf("unsupported bind options")
			}
		case "cgroup":
			allowed = validCgroupMount(m)
		case "proc":
			allowed = m.Source == "proc" && m.Destination == "/proc"
		case "sysfs":
			allowed = m.Source == "sysfs" && m.Destination == "/sys" && containsEvidence(m.Options, "ro")
		case "devpts":
			allowed = m.Source == "devpts" && m.Destination == "/dev/pts"
		case "mqueue":
			allowed = m.Source == "mqueue" && m.Destination == "/dev/mqueue"
		case "tmpfs":
			allowed = (m.Source == "tmpfs" && (m.Destination == "/dev" || m.Destination == "/dev/shm" || m.Destination == "/run")) || (m.Source == "shm" && m.Destination == "/dev/shm")
		}
		if !allowed || (m.Type != "bind" && (containsEvidence(m.Options, "bind") || containsEvidence(m.Options, "rbind"))) {
			return fmt.Errorf("unsupported OCI mount %s at %s: mount provenance is unsupported", m.Type, m.Destination)
		}
	}
	for _, device := range spec.Linux.Devices {
		allowed := device.Type == "c" && ((device.Major == 1 && (device.Minor == 3 || device.Minor == 5 || device.Minor == 7 || device.Minor == 8 || device.Minor == 9)) || (device.Major == 5 && (device.Minor == 0 || device.Minor == 1 || device.Minor == 2)))
		if !allowed {
			return fmt.Errorf("host/block device exposure is unsupported")
		}
	}
	if spec.Linux.Resources != nil {
		for _, device := range spec.Linux.Resources.Devices {
			if device.Allow && (device.Type == "b" || device.Type == "" || device.Type == "a") {
				return fmt.Errorf("privileged/block device cgroup rule")
			}
		}
	}
	return nil
}

// This is deliberately a canonical-template checker, not a general seccomp
// implication solver. The syscall barrier is needed because periodic root
// checks cannot prevent chroot/user-namespace changes between observations.
func validateRootSeccomp(profile *specs.LinuxSeccomp) error {
	if goruntime.GOARCH != "amd64" || profile == nil || profile.DefaultAction != specs.ActAllow || len(profile.Architectures) != 1 || profile.Architectures[0] != specs.ArchX86_64 || len(profile.Syscalls) > 512 {
		return fmt.Errorf("stable-root evidence requires the canonical native-x86_64 seccomp barrier")
	}
	required := map[string]bool{"chroot": false, "pivot_root": false, "unshare": false, "setns": false, "clone3": false}
	flags := map[uint64]bool{uint64(unix.CLONE_NEWUSER): false, uint64(unix.CLONE_NEWNS): false}
	for _, rule := range profile.Syscalls {
		for _, name := range rule.Names {
			if _, ok := required[name]; ok {
				if rule.Action != specs.ActErrno || rule.ErrnoRet == nil || *rule.ErrnoRet != uint(unix.EPERM) || len(rule.Args) != 0 {
					return fmt.Errorf("ambiguous seccomp rule for root-changing syscall %s", name)
				}
				required[name] = true
			}
			if name == "clone" {
				if len(rule.Names) != 1 || rule.Action != specs.ActErrno || rule.ErrnoRet == nil || *rule.ErrnoRet != uint(unix.EPERM) || len(rule.Args) != 1 {
					return fmt.Errorf("ambiguous clone namespace seccomp rule")
				}
				arg := rule.Args[0]
				if _, ok := flags[arg.Value]; !ok || arg.Index != 0 || arg.Op != specs.OpMaskedEqual || arg.ValueTwo != arg.Value {
					return fmt.Errorf("clone rule is not a canonical namespace-bit deny")
				}
				flags[arg.Value] = true
			}
		}
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("missing unconditional seccomp errno deny for %s", name)
		}
	}
	for flag, found := range flags {
		if !found {
			return fmt.Errorf("missing clone namespace-bit deny %#x", flag)
		}
	}
	return nil
}

func containsEvidence(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func validateContainerdEvidence(e containerdImageEvidence, id string, pid uint32) (overlayEvidence, error) {
	var empty overlayEvidence
	if !fullContainerID(id) || e.ID != id || e.Namespace != "k8s.io" || e.PID != pid || pid == 0 || !e.Running || e.Image == "" {
		return empty, fmt.Errorf("runtime container/task identity mismatch")
	}
	if e.SandboxID != "" && (!fullContainerID(e.SandboxID) || e.PodUID == "" || e.PodNamespace == "" || e.Spec == nil || e.Spec.Annotations["io.kubernetes.cri.sandbox-id"] != e.SandboxID || e.Spec.Annotations["io.kubernetes.cri.container-type"] != "container") {
		return empty, fmt.Errorf("OCI identity does not match authenticated CRI sandbox")
	}
	if e.RuntimeName != "io.containerd.runc.v2" {
		return empty, fmt.Errorf("only the trusted runc v2 runtime matrix is supported")
	}
	if e.Snapshotter != "overlayfs" || e.SnapshotKey == "" || len(e.SnapshotKey) > 512 || e.Active.Name != e.SnapshotKey || e.Active.Kind != snapshots.KindActive {
		return empty, fmt.Errorf("unsupported active snapshot evidence")
	}
	if len(e.DiffIDs) == 0 || len(e.DiffIDs) > 128 || len(e.Parents) != len(e.DiffIDs) {
		return empty, fmt.Errorf("incomplete or excessive committed snapshot chain")
	}
	for _, diff := range e.DiffIDs {
		if err := diff.Validate(); err != nil {
			return empty, err
		}
	}
	expected := imageidentity.ChainID(e.DiffIDs).String()
	if e.Active.Parent != expected {
		return empty, fmt.Errorf("active parent does not match image ChainID")
	}
	for i, item := range e.Parents {
		n := len(e.DiffIDs) - i
		parent := ""
		if n > 1 {
			parent = imageidentity.ChainID(e.DiffIDs[:n-1]).String()
		}
		if item.Kind != snapshots.KindCommitted || item.Name != imageidentity.ChainID(e.DiffIDs[:n]).String() || item.Parent != parent {
			return empty, fmt.Errorf("committed snapshot chain mismatch")
		}
	}
	if err := validateImageSpec(e.Spec); err != nil {
		return empty, err
	}
	if len(e.Mounts) != 1 || e.Mounts[0].Type != "overlay" || e.Mounts[0].Source != "overlay" || e.Mounts[0].Target != "" {
		return empty, fmt.Errorf("unsupported snapshot mount specification")
	}
	overlay, err := parseOverlayEvidence(e.Mounts[0].Options)
	if err != nil {
		return empty, err
	}
	if len(overlay.Lower) != len(e.Parents) {
		return empty, fmt.Errorf("snapshot lowerdir/parent count mismatch")
	}
	return overlay, nil
}

type processRootEvidence struct {
	MountID       uint64
	Device, Inode uint64
	Overlay       overlayEvidence
}

func parseProcessRootEvidence(data []byte, mountID uint64) (overlayEvidence, error) {
	var result overlayEvidence
	found := false
	if len(data) > 65536 {
		return result, fmt.Errorf("mountinfo budget exceeded")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return result, fmt.Errorf("malformed mountinfo")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return result, err
		}
		if id != mountID {
			continue
		}
		if found || fields[3] != "/" || fields[4] != "/" {
			return result, fmt.Errorf("pivoted/ambiguous process root")
		}
		found = true
		separator := -1
		for i, f := range fields {
			if f == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+4 != len(fields) || fields[separator+1] != "overlay" || fields[separator+2] != "overlay" {
			return result, fmt.Errorf("process root is not a simple overlay")
		}
		result, err = parseOverlayEvidence(strings.Split(fields[separator+3], ","))
		if err != nil {
			return result, err
		}
	}
	if !found {
		return result, fmt.Errorf("pinned process root mount missing")
	}
	return result, nil
}
func validateLiveRootBarrier(status []byte) error {
	seccomp := false
	sets := map[string]bool{"CapBnd:": false, "CapEff:": false, "CapPrm:": false, "CapInh:": false, "CapAmb:": false}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[0] == "Seccomp:" {
			if fields[1] != "2" {
				return fmt.Errorf("process seccomp filter is not active")
			}
			seccomp = true
		}
		if _, ok := sets[fields[0]]; ok {
			value, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return err
			}
			if value&(uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_SYS_CHROOT|uint64(1)<<unix.CAP_CHECKPOINT_RESTORE) != 0 {
				return fmt.Errorf("live process retains root-changing capabilities")
			}
			sets[fields[0]] = true
		}
	}
	if !seccomp {
		return fmt.Errorf("missing live seccomp state")
	}
	for _, found := range sets {
		if !found {
			return fmt.Errorf("incomplete live capability state")
		}
	}
	return nil
}

func observeProcessRoot(process *linuxLease) (*os.File, processRootEvidence, error) {
	var result processRootEvidence
	if err := process.Check(); err != nil {
		return nil, result, err
	}
	status, err := process.read("status")
	if err != nil {
		return nil, result, err
	}
	if err = validateLiveRootBarrier(status); err != nil {
		return nil, result, err
	}
	fd, err := unix.Openat(int(process.proc.Fd()), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, result, err
	}
	root := os.NewFile(uintptr(fd), "pinned process root")
	fail := func(err error) (*os.File, processRootEvidence, error) {
		return nil, result, errors.Join(err, root.Close())
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.OVERLAYFS_SUPER_MAGIC {
		return fail(fmt.Errorf("process root is not overlay"))
	}
	var stat unix.Statx_t
	if err = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &stat); err != nil {
		return fail(err)
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return fail(fmt.Errorf("root mount identity unavailable"))
	}
	data, err := process.read("mountinfo")
	if err != nil {
		return fail(err)
	}
	overlay, err := parseProcessRootEvidence(data, stat.Mnt_id)
	if err != nil {
		return fail(err)
	}
	result = processRootEvidence{MountID: stat.Mnt_id, Device: unix.Mkdev(stat.Dev_major, stat.Dev_minor), Inode: stat.Ino, Overlay: overlay}
	if err = process.Check(); err != nil {
		return fail(err)
	}
	return root, result, nil
}

func validBindOptions(options []string) bool {
	if len(options) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, option := range options {
		if seen[option] {
			return false
		}
		seen[option] = true
		switch option {
		case "bind", "rbind", "ro", "rw", "rprivate", "private", "rslave", "slave", "nosuid", "nodev", "noexec", "relatime":
		default:
			return false
		}
	}
	return !(seen["ro"] && seen["rw"]) && !(seen["bind"] && seen["rbind"])
}
func sensitiveVolumeSource(source string, lower []lowerLayer) bool {
	for _, root := range []string{"/proc", "/sys", "/dev", "/etc", "/bin", "/sbin", "/usr", "/root", "/run", "/var/run", "/var/lib/containerd", "/var/lib/docker"} {
		if source == root || strings.HasPrefix(source, root+"/") || strings.HasPrefix(root, source+"/") {
			return true
		}
	}
	for _, root := range lower {
		if runtimeRoot, _, ok := strings.Cut(root.name, "/io.containerd.snapshotter.v1.overlayfs/snapshots/"); ok && simpleEvidencePath(runtimeRoot) {
			if source == runtimeRoot || strings.HasPrefix(source, runtimeRoot+"/") || strings.HasPrefix(runtimeRoot, source+"/") {
				return true
			}
		}
		if source == root.name || strings.HasPrefix(source, root.name+"/") || strings.HasPrefix(root.name, source+"/") {
			return true
		}
	}
	return false
}
func mountReadOnly(data []byte, id uint64) (bool, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return false, fmt.Errorf("malformed volume mountinfo")
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return false, err
		}
		if n == id {
			return containsEvidence(strings.Split(fields[5], ","), "ro"), nil
		}
	}
	return false, fmt.Errorf("volume mount not found")
}

type volumeWalker struct {
	ctx            context.Context
	entries        int
	lower          map[ImageInode]bool
	writable       bool
	rejectRedirect bool
	allowSpecial   bool
}

func (w *volumeWalker) walk(file *os.File, name string, depth int, h hash.Hash) (retErr error) {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth > 128 || len(name) > 4096 {
		return fmt.Errorf("volume traversal depth/path exceeded")
	}
	stat, err := indexStat(file)
	if err != nil {
		return err
	}
	fmt.Fprintf(h, "%q:%+v\n", name, stat)
	if w.rejectRedirect && (stat.Mode&unix.S_IFMT == unix.S_IFREG || stat.Mode&unix.S_IFMT == unix.S_IFDIR) {
		// The self-fd path targets an already pinned inode; it is not a workload
		// pathname or an untrusted process magic link. O_PATH cannot use fgetxattr.
		for _, attribute := range []string{"trusted.overlay.redirect", "user.overlay.redirect"} {
			_, e := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", file.Fd()), attribute, nil)
			if e == nil {
				return fmt.Errorf("redirected lower layer is unsupported")
			}
			if !errors.Is(e, unix.ENODATA) {
				return fmt.Errorf("cannot prove absence of lower redirects: %w", e)
			}
		}
	}

	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if w.writable && w.lower[ImageInode{stat.Ino, unix.Major(stat.Dev), unix.Minor(stat.Dev)}] {
			return fmt.Errorf("writable volume aliases immutable image inode")
		}
		return nil
	case unix.S_IFLNK:
		return nil // never follow projected-directory symlinks while enumerating
	case unix.S_IFDIR:
	default:
		if w.allowSpecial {
			return nil
		}
		return fmt.Errorf("volume exposes socket/device/special file")
	}
	reader, err := indexOpen(int(file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, true)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, reader.Close()) }()
	var names []string
	for {
		batch, e := reader.Readdirnames(128)
		for _, name := range batch {
			w.entries++
			if w.entries > 262144 {
				return fmt.Errorf("volume entry budget exceeded")
			}
			names = append(names, name)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if e = w.ctx.Err(); e != nil {
			return e
		}
	}
	sort.Strings(names)
	for _, childName := range names {
		child, e := indexOpen(int(file.Fd()), childName, unix.O_PATH|unix.O_NOFOLLOW, true)
		if e != nil {
			return e
		}
		e = w.walk(child, path.Join(name, childName), depth+1, h)
		ce := child.Close()
		if e != nil || ce != nil {
			return errors.Join(e, ce)
		}
	}
	after, err := indexStat(file)
	if err != nil {
		return err
	}
	if after != stat {
		return fmt.Errorf("volume changed during provenance scan")
	}
	return nil
}
func validateBindVolumes(ctx context.Context, evidence containerdImageEvidence, index *lowerIndexLease, root *os.File, process *linuxLease) error {
	lower := make(map[ImageInode]bool, len(index.Inodes))
	for _, key := range index.Inodes {
		lower[key] = true
	}
	mountinfo, err := process.read("mountinfo")
	if err != nil {
		return err
	}
	if err := validateCgroupMounts(evidence.Spec, root, mountinfo); err != nil {
		return err
	}
	totalEntries := 0
	var selfMountInfo []byte
	for _, m := range evidence.Spec.Mounts {
		if m.Type != "bind" {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		generated := validatedSandboxFile(evidence, m, index.layers)
		sharedMemory := validatedSandboxShm(evidence, m)
		if sharedMemory && selfMountInfo == nil {
			selfMountInfo, err = readSelfMountInfo()
			if err != nil {
				return err
			}
		}
		if sensitiveVolumeSource(m.Source, index.layers) && !generated && !sharedMemory {
			return fmt.Errorf("bind source exposes sensitive host/runtime/lower roots; no authenticated sandbox-mount provenance")
		}

		source, e := indexOpen(int(index.host.Fd()), strings.TrimPrefix(m.Source, "/"), unix.O_PATH, false)
		if e != nil {
			return e
		}
		// Absolute paths and /var/run symlinks resolve within the pinned container
		// root; proc magic links cannot escape it. Ordinary symlinks are permitted.
		fd, e := unix.Openat2(int(root.Fd()), m.Destination, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if e != nil {
			return errors.Join(e, source.Close())
		}
		destination := os.NewFile(uintptr(fd), m.Destination)
		check := func() error {
			src, e := indexStat(source)
			if e != nil {
				return e
			}
			dst, e := indexStat(destination)
			if e != nil {
				return e
			}
			if src.Dev != dst.Dev || src.Ino != dst.Ino || src.Mode&unix.S_IFMT != dst.Mode&unix.S_IFMT {
				return fmt.Errorf("bind source/destination inode mismatch")
			}
			if sharedMemory {
				if e = validateSandboxShmPins(source, destination, selfMountInfo, mountinfo, evidence, process); e != nil {
					return e
				}
			}
			if generated && src.Mode&unix.S_IFMT != unix.S_IFREG {
				return fmt.Errorf("authenticated sandbox file is not regular")
			}
			if src.Mode&unix.S_IFMT != unix.S_IFREG && src.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fmt.Errorf("bind source is not an ordinary file/directory")
			}
			if e = indexFS(source); e != nil {
				return e
			}
			var sx unix.Statx_t
			if e = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx); e != nil {
				return e
			}
			if sx.Mask&unix.STATX_MNT_ID == 0 {
				return fmt.Errorf("bind mount identity unavailable")
			}
			ro, e := mountReadOnly(mountinfo, sx.Mnt_id)
			if e != nil {
				return e
			}
			if containsEvidence(m.Options, "ro") && !ro {
				return fmt.Errorf("read-only OCI bind is writable in process mount namespace")
			}
			walker := volumeWalker{ctx: ctx, entries: totalEntries, lower: lower, writable: !ro}
			a, b := sha256.New(), sha256.New()
			if e = walker.walk(source, "/", 0, a); e != nil {
				return e
			}
			if e = walker.walk(destination, "/", 0, b); e != nil {
				return e
			}
			totalEntries = walker.entries
			if string(a.Sum(nil)) != string(b.Sum(nil)) {
				return fmt.Errorf("bind tree changed or has different nested mounts")
			}
			return nil
		}
		e = check()
		ce := errors.Join(source.Close(), destination.Close())
		if e != nil || ce != nil {
			return errors.Join(e, ce)
		}
	}
	return nil
}

type trustedImageLease struct {
	mu           sync.Mutex
	Inodes       []ImageInode
	Complete     bool
	source       imageEvidenceSource
	process      *linuxLease // borrowed: caller must retain it until this lease closes
	root         *os.File
	index        *lowerIndexLease
	rootEvidence processRootEvidence
	evidenceHash [32]byte
	failure      error
	closed       bool
}

func evidenceHash(e containerdImageEvidence) ([32]byte, error) {
	b, err := json.Marshal(e)
	return sha256.Sum256(b), err
}

// Host/runtime privilege and immutable runtime layers are trusted. This rejects
// unproved mounts rather than pretending annotations establish immunity. No
// support for Docker, unvalidated bind aliases, redirected/data-only/nested overlay lowers,
// pivoted roots, shared PID/mount namespaces or arbitrary runtime layouts.
func acquireImageEvidence(ctx context.Context, source imageEvidenceSource, process *linuxLease, hostRoot string, limits ImageIndexLimits) (*trustedImageLease, error) {
	if source == nil || process == nil || process.identity.Runtime != "containerd" {
		return nil, fmt.Errorf("trusted containerd process lease required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	evidence, err := source.Evidence(ctx, process.identity.ContainerID)
	if err != nil {
		return nil, err
	}
	if err := validateEvidencePodIdentity(evidence, process); err != nil {
		return nil, err
	}
	overlay, err := validateContainerdEvidence(evidence, process.identity.ContainerID, process.identity.PID)
	if err != nil {
		return nil, err
	}
	root, observed, err := observeProcessRoot(process)
	if err != nil {
		return nil, err
	}
	lease := &trustedImageLease{source: source, process: process, root: root, rootEvidence: observed}
	fail := func(err error) (*trustedImageLease, error) { return nil, errors.Join(err, lease.Close()) }
	if !sameOverlay(overlay, observed.Overlay) {
		return fail(fmt.Errorf("runtime snapshot does not match pinned process root"))
	}
	lease.evidenceHash, err = evidenceHash(evidence)
	if err != nil {
		return fail(err)
	}
	lease.index, err = buildLowerIndex(ctx, hostRoot, overlay.Lower, limits)
	if err != nil {
		return fail(err)
	}
	if err = lease.check(ctx); err != nil {
		return fail(err)
	}
	lease.Inodes = append([]ImageInode(nil), lease.index.Inodes...)
	lease.Complete = true
	return lease, nil
}
func sameOverlay(a, b overlayEvidence) bool {
	if a.Upper != b.Upper || a.Work != b.Work || len(a.Lower) != len(b.Lower) {
		return false
	}
	for i := range a.Lower {
		if a.Lower[i] != b.Lower[i] {
			return false
		}
	}
	return true
}

// imageEvidenceUnavailable marks only retrieval transport failures. Validation,
// root/index checks and unsafe-volume errors must not inherit this exemption.
type imageEvidenceUnavailable struct{ err error }

func (e *imageEvidenceUnavailable) Error() string { return e.err.Error() }
func (e *imageEvidenceUnavailable) Unwrap() error { return e.err }

func transientImageEvidenceRetrieval(err error) bool {
	if errdefs.IsUnavailable(err) || status.Code(err) == codes.Unavailable {
		return true
	}
	// Require network provenance: a bare EOF may instead be malformed runtime
	// metadata, and filesystem failures are not evidence-source unavailability.
	var op *net.OpError
	return errors.As(err, &op) && (errors.Is(op, unix.ECONNREFUSED) ||
		errors.Is(op, unix.ECONNRESET) || errors.Is(op, unix.EPIPE) || errors.Is(op, io.EOF))
}

func (l *trustedImageLease) check(ctx context.Context) error {
	if l.closed {
		return fmt.Errorf("image evidence lease closed")
	}
	if l.failure != nil {
		return l.failure
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	evidence, err := l.source.Evidence(ctx, l.process.identity.ContainerID)
	if err != nil {
		if transientImageEvidenceRetrieval(err) {
			return &imageEvidenceUnavailable{err: err}
		}
		return err
	}
	if err = validateEvidencePodIdentity(evidence, l.process); err != nil {
		return err
	}
	if _, err = validateContainerdEvidence(evidence, l.process.identity.ContainerID, l.process.identity.PID); err != nil {
		return err
	}
	sum, err := evidenceHash(evidence)
	if err != nil {
		return err
	}
	if sum != l.evidenceHash {
		return fmt.Errorf("runtime image evidence changed")
	}
	root, current, err := observeProcessRoot(l.process)
	if err != nil {
		return err
	}
	if err = root.Close(); err != nil {
		return err
	}
	before := l.rootEvidence
	if current.MountID != before.MountID || current.Device != before.Device || current.Inode != before.Inode || !sameOverlay(current.Overlay, before.Overlay) {
		return fmt.Errorf("process root evidence changed")
	}
	if err := l.index.CheckContext(ctx); err != nil {
		return err
	}
	walker := volumeWalker{ctx: ctx, rejectRedirect: true, allowSpecial: true}
	for _, layer := range l.index.layers {
		if err = walker.walk(layer.file, "/", 0, sha256.New()); err != nil {
			return err
		}
	}
	if err = validateBindVolumes(ctx, evidence, l.index, l.root, l.process); err != nil {
		return err
	}
	return l.process.Check()
}
func (l *trustedImageLease) Check() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.CheckContext(ctx)
}

// CheckContext preserves the sticky evidence-failure boundary while allowing the
// persistent owner to bound runtime re-attestation with its operation context.
func (l *trustedImageLease) CheckContext(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.check(ctx)
	// An interrupted observation is not evidence that the pinned root changed.
	// Likewise, transport unavailability cannot attest a change. Fail this
	// operation, but permit a later full re-attestation of the same pinned lease.
	var unavailable *imageEvidenceUnavailable
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &unavailable) {
		l.Complete = false
		l.failure = err
	}
	return err
}
func (l *trustedImageLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.Complete = false
	var errs []error
	if l.index != nil {
		errs = append(errs, l.index.Close())
	}
	if l.root != nil {
		errs = append(errs, l.root.Close())
	}
	return errors.Join(errs...)
}
