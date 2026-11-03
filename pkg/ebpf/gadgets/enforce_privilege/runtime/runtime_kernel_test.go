//go:build linux && privilege_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

// Opt-in test of the gadget with Inspektor Gadget alone: it parses the example
// policy file, starts the gadget from an OCI archive and binds one Docker
// container through this package's operator. Requires root, BPF LSM and a
// disposable container started with seccomp=unconfined and --cap-add SYS_ADMIN:
//
//	PRIVILEGE_KERNEL_TEST=1
//	PRIVILEGE_IMAGE_ARCHIVE  OCI archive from `ig image export`
//	PRIVILEGE_IMAGE          image name in the archive
//	PRIVILEGE_CONTAINER_ID   full Docker container ID
//	PRIVILEGE_CGROUP_PATH    its cgroup v2 path under /sys/fs/cgroup, with a leading "/" (as in /proc/<pid>/cgroup)

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"golang.org/x/sys/unix"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

func TestGadgetWithInspektorGadgetAlone(t *testing.T) {
	if os.Getenv("PRIVILEGE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	f, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := privpolicy.Parse(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	id, cgroupPath := os.Getenv("PRIVILEGE_CONTAINER_ID"), os.Getenv("PRIVILEGE_CGROUP_PATH")
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	container := ContainerIdentity{Runtime: "docker", ID: id, CgroupID: st.Ino, CgroupPath: cgroupPath}

	store, err := orasoci.NewFromTar(ctx, os.Getenv("PRIVILEGE_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err := rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	manager, err := instancemanager.New(rt)
	if err != nil {
		t.Fatal(err)
	}
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		t.Fatal(err)
	}
	if err := handler.Init(params); err != nil {
		t.Fatal(err)
	}
	var verdicts atomic.Int32
	var bindings *enforcement.Bindings
	events := simple.New("privilege-test-verdicts", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		var err error
		if bindings, err = GetBindings(gc); err != nil {
			return err
		}
		return gc.GetDataSources()["verdict"].Subscribe(func(datasource.DataSource, datasource.Data) error {
			verdicts.Add(1)
			return nil
		}, 100)
	}))
	runtimeMntns, err := enforcement.RuntimeMountNamespace()
	if err != nil {
		t.Fatal(err)
	}
	desired := &api.GadgetInstance{Id: "privilege-kernel-test", GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: os.Getenv("PRIVILEGE_IMAGE"),
		ParamValues: map[string]string{"operator.oci.ebpf.host-mntns-id": strconv.FormatUint(runtimeMntns, 10)}}}
	if err := manager.StartGadget(ctx, desired, gadgetcontext.WithOrasReadonlyTarget(store),
		gadgetcontext.WithAdditionalDataOperators(handler, New(), events),
		WithConfig(Config{Policy: compiled})); err != nil {
		t.Fatal(err)
	}
	defer manager.StopGadget(context.Background(), desired.Id)

	unshare := func() error { return exec.CommandContext(ctx, "docker", "exec", id, "unshare", "-m", "true").Run() }
	if err := unshare(); err != nil {
		t.Fatalf("unbound container must not be judged: %v", err)
	}
	if err := bindings.Bind(enforcement.Binding{Container: container}); err != nil {
		t.Fatal(err)
	}
	if unshare() == nil {
		t.Fatal("the example policy denies unshare(CLONE_NEWNS) in a bound container")
	}
	if err := bindings.Unbind(container); err != nil {
		t.Fatal(err)
	}
	if err := unshare(); err != nil {
		t.Fatalf("unbound again must be allowed: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if verdicts.Load() == 0 {
		t.Fatal("no verdict event for the deny")
	}
}
