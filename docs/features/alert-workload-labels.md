# Workload labels on alerts

A rule alert carries the labels of the pod (`podLabels`) and the kind, name and UID of the pod's
top-level workload. It now also carries the labels of that workload, in
`RuntimeAlertK8sDetails.WorkloadLabels` (JSON `workloadLabels`).

## Why

A label that identifies a workload can be on the owner and not on the pod. A pod that a Job
creates gets the standard Job labels (`job-name`, `controller-uid`), and a label set on the Job
itself is not copied to the pod. A consumer that groups alerts by such a label could not do it
from `podLabels` alone.

## Behavior

| Case | Value | JSON |
|------|-------|------|
| The pod has no owner, so the workload is the pod itself | nil | field absent |
| The owner has labels | the labels | `"workloadLabels": {"k": "v"}` |
| The owner has no labels | empty map | `"workloadLabels": {}` |

The empty map is sent on purpose. A consumer can then tell an owner with no labels from an agent
that predates the field: a workload kind that is not `Pod` with no `workloadLabels` field means
an older agent. The JSON tag in `armoapi-go` is `omitzero` for this reason.

The top-level workload is the one that the agent resolves by following the owner references
upward, and it is the one that the alert names in `workloadKind` and `workloadName`. The labels
always belong to that same object:

- When no owner can be fetched, for example a custom resource that the agent's role cannot
  read, the pod is its own workload and the field is absent.
- When the walk stops part way, the labels are those of the object where it stopped. A pod
  whose ReplicaSet can be read and whose Deployment cannot is reported with the workload kind
  `ReplicaSet` and the labels of the ReplicaSet.

## How it works

1. When a container starts, `getSharedWatchedContainerData`
   (`pkg/containerwatcher/v2/containercallback.go`) already fetches the top-level workload to
   build the WLID. It now keeps a copy of the workload's labels in
   `WatchedContainerData.WorkloadLabels`. No Kubernetes API call is added.
2. The rule manager binds a pod to its workload when the pod's first container is registered
   (`bindPodWorkload` in `pkg/rulemanager/rule_manager.go`). It stores the WLID and the labels
   together, from the same shared container data.
3. When a rule fails, the rule manager sets the workload identity on the alert from the WLID,
   and the labels from the same binding (`setWorkloadLabels`).

The identity and the labels are one snapshot with one lifetime. The container watcher deletes
the shared container data as soon as a container is removed, while events of that container can
still be evaluated. The rule manager keeps the binding of a pod for 10 minutes after its last
container was removed, so an alert created in that window names the workload and carries its
labels. An alert never names a workload other than `Pod` without `workloadLabels`.

The labels are read once, when the pod's first container starts. A later change of the owner's
labels is not reflected on alerts of that pod.

## Limits

- The host pseudo-container has no workload, and its alerts carry no `workloadLabels`.
- Only rule alerts carry the field. Malware alerts do not.
- A service that encodes the alert again with a JSON library other than `encoding/json` of
  Go 1.24 or later must check that the library keeps the empty map.
