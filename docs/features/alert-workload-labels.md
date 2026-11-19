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

The pod is its own workload also when its owner cannot be fetched, for example a custom resource
that the agent's role cannot read. The field is absent in that case.

## How it works

1. When a container starts, `getSharedWatchedContainerData`
   (`pkg/containerwatcher/v2/containercallback.go`) already fetches the top-level workload to
   build the WLID. It now keeps a copy of the workload's labels in
   `WatchedContainerData.WorkloadLabels`. No Kubernetes API call is added.
2. When a rule fails, `setRuntimeAlertK8sDetails` (`pkg/rulemanager/ruleadapters/creator.go`)
   copies the labels from the shared container data to the alert, next to `WorkloadUID`.

The labels are read once, at container start. A later change of the owner's labels is not
reflected on alerts of containers that already run.

## Limits

- The host pseudo-container has no workload, and its alerts carry no `workloadLabels`.
- Only alerts built by the rule failure creator carry the field. Malware alerts do not.
- A service that encodes the alert again with a JSON library other than `encoding/json` of
  Go 1.24 or later must check that the library keeps the empty map.
