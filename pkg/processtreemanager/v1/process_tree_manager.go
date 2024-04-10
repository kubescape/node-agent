package processtreemanager

import (
	"fmt"
	"node-agent/pkg/processtreemanager"
	"node-agent/pkg/utils"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/go-logger"
)

var _ processtreemanager.ProcessTreeManagerClient = (*ProcessTreeManager)(nil)

type ProcessTreeManager struct {
	Trees        maps.SafeMap[string, apitypes.Process]                // Map of container ID to the root process of the tree.
	TreeTracking maps.SafeMap[string, processtreemanager.TreeTracking] // Map of container ID to the tracking information.
}

func NewProcessTreeManager() *ProcessTreeManager {
	return &ProcessTreeManager{}
}

func (ptm *ProcessTreeManager) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		// Add the new container to the tree with virtual root.
		ptm.Trees.Set(notif.Container.Runtime.ContainerID, apitypes.Process{
			PID: 0,
		})
		ptm.TreeTracking.Set(notif.Container.Runtime.ContainerID, processtreemanager.TreeTracking{
			UniqueID: 0,
			Sent:     false,
		})
	case containercollection.EventTypeRemoveContainer:
		ptm.Trees.Delete(notif.Container.Runtime.ContainerID)
		ptm.TreeTracking.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (ptm *ProcessTreeManager) GetProcessTreeByContainerId(containerID string) (apitypes.Process, error) {
	if !ptm.Trees.Has(containerID) {
		return apitypes.Process{}, fmt.Errorf("container id not found in process tree map")
	}

	return ptm.Trees.Get(containerID), nil
}

func (ptm *ProcessTreeManager) GetTreeTrackingByContainerId(containerID string) (processtreemanager.TreeTracking, error) {
	if !ptm.TreeTracking.Has(containerID) {
		return processtreemanager.TreeTracking{}, fmt.Errorf("container id not found in tree tracking map")
	}

	return ptm.TreeTracking.Get(containerID), nil
}

func (ptm *ProcessTreeManager) GetProcessByPid(proc *apitypes.Process, pid uint32) *apitypes.Process {
	if proc == nil {
		return nil
	}

	if proc.PID == pid {
		return proc
	}

	for _, p := range proc.Children {
		if found := ptm.GetProcessByPid(&p, pid); found != nil {
			return found
		}
	}

	return nil
}

// When a file is executed, the process tree manager should add the new process to the tree.
func (ptm *ProcessTreeManager) ReportFileExec(event tracerexectype.Event) {
	if ptm.Trees.Has(event.Runtime.ContainerID) {
		newProcess := apitypes.Process{
			PID:        event.Pid,
			Cmdline:    getCmdline(&event),
			Comm:       event.Comm,
			PPID:       event.Ppid,
			Pcomm:      event.Pcomm,
			Hardlink:   event.ExePath,
			Uid:        event.Uid,
			Gid:        event.Gid,
			UpperLayer: event.UpperLayer,
			Cwd:        event.Cwd,
		}
		// If the parent is already in the tree, add the new process as a child.
		root := ptm.Trees.Get(event.Runtime.ContainerID)
		root = ptm.fixTree(root, event.Pid)
		if !ptm.addChildProcess(&root, newProcess) {
			// Add the new process as a root.
			root.Children = append(root.Children, newProcess)
		}
		ptm.Trees.Set(event.Runtime.ContainerID, root)
		treeTracking := ptm.TreeTracking.Get(event.Runtime.ContainerID)
		treeTracking.UniqueID = treeTracking.UniqueID + 1
		treeTracking.Sent = false
		ptm.TreeTracking.Set(event.Runtime.ContainerID, treeTracking)
	} else {
		logger.L().Error("Container id not found in process tree map")
	}
}

// Recursively add a child process to the tree.
// root is the root of the tree. (PID = 0)
func (ptm *ProcessTreeManager) addChildProcess(root *apitypes.Process, child apitypes.Process) bool {
	if root.PID == 0 {
		for _, p := range root.Children {
			if ptm.addChildProcess(&p, child) {
				return true
			}
		}
		return false
	}

	if root.PID == child.PPID {
		root.Children = append(root.Children, child)
		return true
	}

	for _, p := range root.Children {
		if ptm.addChildProcess(&p, child) {
			return true
		}
	}

	return false
}

// Given a pid, checks if it already exists, if so, remove it from the tree /
// and move it's children to the parent.
// TODO: This is temporary, until we have a tracer to tell us when a process dies.
func (ptm *ProcessTreeManager) fixTree(tree apitypes.Process, pid uint32) apitypes.Process {
	newChildren := []apitypes.Process{}
	for _, child := range tree.Children {
		if child.PID != pid {
			ptm.fixTree(child, pid)
			newChildren = append(newChildren, child)
		} else {
			// Move the children of the process with the given PID to its parent
			newChildren = append(newChildren, child.Children...)
			// Do not add the child to newChildren to remove it from the tree
			continue
		}
	}
	tree.Children = newChildren
	return tree
}

func getCmdline(event *tracerexectype.Event) string {
	if len(event.Args) == 0 {
		return event.Comm
	}

	return fmt.Sprintf("%s %s", utils.GetExecPathFromEvent(event), strings.Join(event.Args[1:], " "))
}
