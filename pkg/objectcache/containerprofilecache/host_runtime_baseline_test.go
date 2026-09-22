package containerprofilecache

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

// Exercise the production cache lookup, profile helper, and CEL evaluator together.
// Only the remote storage transport is replaced by an in-memory profile server.
func TestKubernetesHostRuntimeBaselineDecision(t *testing.T) {
	identity := armotypes.KubernetesHostIdentity{Version: 1, ClusterUID: "cluster-uid", ClusterName: "cluster-a", NodeUID: "node-uid", NodeName: "node-a"}
	var err error
	identity.MachineFingerprint, err = armotypes.KubernetesHostMachineFingerprint("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	identity.Key, err = armotypes.KubernetesHostKey(identity.ClusterUID, identity.NodeUID, identity.MachineFingerprint)
	require.NoError(t, err)
	data := hostidentity.BuildKubernetesHostWatchedContainerData(identity)
	child, err := data.InstanceID.GetSlug(false)
	require.NoError(t, err)
	client := &generationProfileClient{t: t, profiles: map[string]*v1beta1.ContainerProfile{
		child: {Name: child, Namespace: "kubescape", ResourceVersion: "1", Annotations: map[string]string{
			helpersv1.StatusMetadataKey: helpersv1.Completed, helpersv1.CompletionMetadataKey: helpersv1.Full,
		}, Spec: v1beta1.ContainerProfileSpec{Syscalls: []string{"openat"}}},
	}}
	load := func(id armotypes.KubernetesHostIdentity) (*ContainerProfileCacheImpl, objectcache.ObjectCache, *cel.CEL) {
		c, k8s := newTestCache(t, client)
		c.cfg.NamespaceName = "kubescape"
		c.SetProjectionSpec(objectcache.RuleProjectionSpec{Hash: "syscalls", Syscalls: objectcache.FieldSpec{InUse: true, All: true}})
		k8s.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildKubernetesHostWatchedContainerData(id))
		container := hostEventContainer()
		container.K8s.Namespace = "kubescape"
		require.NoError(t, c.addContainer(container, t.Context()))
		objects := objectcachev1.NewObjectCache(k8s, c, nil)
		evaluator, err := cel.NewCEL(objects, config.Config{})
		require.NoError(t, err)
		return c, objects, evaluator
	}
	evaluate := func(evaluator *cel.CEL, syscall, expression string) bool {
		event := &events.EnrichedEvent{ContainerID: armotypes.HostContainerID, Event: &utils.StructEvent{
			ContainerID: armotypes.HostContainerID, EventType: utils.SyscallEventType, Syscall: syscall,
		}}
		alert, err := evaluator.EvaluateRule(event, []typesv1.RuleExpression{{EventType: utils.SyscallEventType, Expression: expression}})
		require.NoError(t, err)
		return alert
	}
	const learned = `cp.was_syscall_used("host", event.syscallName)`
	const unexpected = `!cp.was_syscall_used("host", event.syscallName)`
	for _, phase := range []string{"initial", "restart"} {
		t.Run(phase, func(t *testing.T) {
			c, objects, evaluator := load(identity)
			require.Equal(t, child, c.GetContainerProfileState(armotypes.HostContainerID).Name)
			_, _, err := profilehelper.GetProjectedContainerProfile(objects, armotypes.HostContainerID)
			require.NoError(t, err)
			// Both polarities prevent a disabled or uncompilable rule from passing.
			require.True(t, evaluate(evaluator, "openat", learned))
			require.False(t, evaluate(evaluator, "openat", unexpected))
			require.False(t, evaluate(evaluator, "execve", learned))
			require.True(t, evaluate(evaluator, "execve", unexpected))
		})
	}
	previous := identity.Key
	identity.NodeUID = "replacement-node"
	identity.MachineFingerprint, err = armotypes.KubernetesHostMachineFingerprint("fedcba9876543210fedcba9876543210")
	require.NoError(t, err)
	identity.Key, err = armotypes.KubernetesHostKey(identity.ClusterUID, identity.NodeUID, identity.MachineFingerprint)
	require.NoError(t, err)
	require.NotEqual(t, previous, identity.Key)
	c, objects, evaluator := load(identity)
	require.Nil(t, c.GetProjectedContainerProfile(armotypes.HostContainerID))
	_, _, err = profilehelper.GetProjectedContainerProfile(objects, armotypes.HostContainerID)
	require.Error(t, err, "replacement has no eligible baseline")
	require.False(t, evaluate(evaluator, "openat", learned), "predecessor behavior must not be inherited")
	require.Contains(t, client.profiles, child, "predecessor profile remains as history")
}
