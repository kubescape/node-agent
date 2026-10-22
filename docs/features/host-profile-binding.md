# Host profile binding

In Kubernetes, enable `hostMonitoringEnabled` and
`applicationProfileServiceEnabled` to learn the host's ContainerProfile. Enable
`runtimeDetectionEnabled` to evaluate rules against it. Profiles are stored in
the node-agent deployment namespace.

To use an authored ContainerProfile for a host, create it in that namespace and
label the Node running the agent:

```sh
kubectl label node <node-name> kubescape.io/user-defined-profile=<profile-name> --overwrite
```

The profile cache reads the Node label at registration and on its refresh ticks.
Changing the label selects a different authored profile; removing it returns to
the learned profile. A failed Node lookup retains the last observed binding;
it does not count as label removal. The agent needs `get` permission on Nodes,
which the test chart already grants.

Host network observations are learned for the synthetic `host` container.
Network tracing must also be enabled (`networkServiceEnabled` or
`runtimeDetectionEnabled`, with `dNetwork` disabled).
Ordinary Pods using `hostNetwork` remain excluded from network profile learning.
The test chart enables host context for R0001, R0002, R0003, R0004 and R0040.
Other rule deployments must opt those rules into `context:host` themselves.
Required-profile rules remain suppressed while their baseline is unavailable.

## Identity and configuration compatibility

Binding a Node label does not rename existing profiles. The shared host identity
continues to use the existing synthetic `host` namespace and
`wlid://cluster-unknown/namespace-host/host-<hostID>`; the Kubernetes storage
namespace is the agent deployment namespace. See
[host monitoring completion](host-monitoring-completion.md) for the identity
builder and learning lifecycle.

A Node identity with the actual cluster name, node artifact labels and a
hostname selector would change profile keys and downstream lookup/cleanup
contracts. Such a migration needs coordinated storage and consumer support,
plus an explicit policy for existing baselines and node replacement. It should
not be introduced by changing the builder in place.

There is no separate `hostProfileServiceEnabled` switch. The existing host
monitoring and application profiling switches continue to control collection.
An independent host profiling switch could later provide host/container cost
control, but its default must preserve existing host learning, and disabling
learning must have defined behavior for bound profiles and required rules.
