# Network-stream entity keying

The network stream groups a flush interval's connections into **entities**: one per
container, plus one for the node itself. Downstream, the entity is the unit a finding
is attributed to, so two workloads sharing an entity are indistinguishable to every
consumer of the stream.

This document covers how an event picks its entity, in `pkg/networkstream/v1`. The
per-connection process identity carried inside an entity is a separate concern — see
[network-stream-process-attribution.md](network-stream-process-attribution.md).

## The rule

```go
entityID := event.GetContainerID()
if entityID == "" || entityID == armotypes.HostContainerID {
    entityID = nodeName          // the node's own traffic
}
```

Only traffic that is not a container's collapses onto the node entity: an event with
no container ID, or with the `"host"` sentinel that `procfs.go` assigns to processes
outside every tracked mount namespace. Everything else keys by container ID.

## What this replaced

The node fallback used to fire on `ns.k8sObjectCache == nil` as well:

```go
if entityId == "" || ns.k8sObjectCache == nil {
    entityId = ns.nodeName
}
```

The object cache is a Kubernetes API cache. In this repo's binary it is always
present, but embedders that run the sensor outside a cluster — on a host, or on an
AWS ECS instance — construct the stream with a nil cache. There *every* event,
including every container's, was folded onto the single node entity: an ECS task's
containers all reported as the instance, and per-workload attribution downstream was
impossible.

The keying on Kubernetes is unchanged. There the cache is always non-nil, so the
removed disjunct was never the reason an event moved to the node.

## Outside Kubernetes, entities are created on first sight

An entity is normally announced by `ContainerCallback`. An event for an entity that
does not exist is logged and dropped.

That drop is why the keying fix alone is not enough outside Kubernetes: the embedders
above do not subscribe this package's `ContainerCallback` at all, so no container
entity is ever announced and every container event would key to an ID that is not in
the map. When `kubernetesMode` is off, `entityForEventLocked` therefore creates a
container entity the first time it sees one, carrying the container ID and nothing
else — the pod and workload fields stay empty until something announces the container.

**In Kubernetes it keeps dropping**, which is what makes this change inert there. A
missing entity in a cluster does not mean "never announced"; it means the container
was removed or is ignored. And a removal is not quiet: the container collection
publishes `EventTypeRemoveContainer` *before* the container leaves the collection and
then keeps it in a 2-second cache for enrichers, while node-agent dispatches this
callback onto a worker pool — so events for a container that is already gone keep
arriving for a while after it dies. Creating an entity for them would put a container
with no pod or workload identity into the payload, for a pod that no longer exists,
on every pod termination.

Where `ContainerCallback` does run, the two can arrive in either order and neither
destroys the other's work. If the announcement came first, the entity already exists
and the event path leaves its identity fields alone. If it came second — which is
routine, because the container watcher submits the callback to a worker pool while
events flow straight through, so a container's first egress lands before it is
announced — it fills the identity in over the event maps already there instead of
replacing them.

The node entity is excluded from that merge. It is not announced; it is created at
construction and remade by every flush, so there is no unannounced window to rescue,
and excluding it means announcing the virtual host container behaves exactly as it
did before.

## Unannounced entities are pruned when they go quiet

An entity born from an event has no container lifecycle behind it — the callback that
would deliver its removal is the one that was missing in the first place. Left alone
it would sit in the map forever and ride along in every later payload, which on a host
with container churn grows without bound.

`snapshotAndClear` deletes such an entity after an interval with no traffic on it. The
set of entities this applies to is tracked explicitly (`unannouncedEntities`) rather
than inferred from an empty metadata field, because pruning an *announced* entity would
throw away the workload identity `enrichWorkloadDetails` resolved and never recover it.
`ContainerCallback` clears the mark, so once a container is announced — in either order
relative to its first event — silence stops meaning "gone".

A merely idle container costs one entity re-creation on its next event.

## Kubernetes-mode enrichment is guarded

`buildNetworkEvent` enriches pod- and service-kind destination endpoints from
`common.K8sInventoryCache`, which is only built when `cfg.KubernetesMode` is set. The
lookups are now behind a nil check, so a pod- or service-kind endpoint arriving
anywhere else leaves the connection unenriched instead of dereferencing a nil
interface.
