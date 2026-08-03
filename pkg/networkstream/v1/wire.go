package networkstream

import (
	"unicode/utf8"

	"github.com/armosec/armoapi-go/armotypes"
)

// maxCmdlineBytes caps each process node's command line ON THE WIRE COPY ONLY.
// cmdline is ~40% of a tree's bytes and unbounded, so it is the lever that keeps
// the payload tail bounded: the worst observed message lands near 2 MB at p90
// tree size against a 5 MiB limit (SUB-7850), and one pathological java or node
// command line can exceed 100 KB on its own. 1024 bytes keeps >99% of real
// command lines intact.
//
// The legacy alert paths and the notification-channel consumer keep the UNCAPPED
// value — never apply this to a node they share.
const maxCmdlineBytes = 1024

// cmdlineTruncationMarker makes a cut visible to a human reading the payload. It
// is charged against the budget, so a capped value is never longer than
// maxCmdlineBytes.
const cmdlineTruncationMarker = "…"

// maxTreeDepth bounds every recursive tree walk here. Real chains are ~10 nodes
// deep; this exists so a malformed or cyclic tree costs a truncated payload
// rather than the agent's stack.
const maxTreeDepth = 64

// buildWireStream derives the HTTP payload from the flush snapshot: per-event
// trees move into the message-scoped Processes map — one capped copy per distinct
// ProcessRef, because trees dominate the payload cost and the extra map entries
// do not — events keep only their ref, and the attribution version marker is
// stamped unconditionally, since an upgraded sensor with nothing to attribute
// must stay distinguishable from a sensor that predates attribution.
//
// The snapshot is NEVER mutated. The notification-channel consumer
// (private-node-agent's host network sensor) holds it and reads
// event.ProcessTree, and the trees themselves are shared with the process-tree
// manager's cache and the legacy alert paths.
//
// Runs OUTSIDE eventsStorageMutex: this is the only expensive part of a flush,
// and holding the lock across it would stall event recording.
func buildWireStream(snapshot *armotypes.NetworkStream) *armotypes.NetworkStream {
	wire := &armotypes.NetworkStream{
		ProcessAttributionVersion: armotypes.NetworkStreamProcessAttributionV1,
	}
	if snapshot == nil {
		return wire
	}

	wire.Entities = make(map[string]armotypes.NetworkStreamEntity, len(snapshot.Entities))
	wire.Processes = make(map[armotypes.ProcessRef]*armotypes.ProcessTree)
	for entityID, entity := range snapshot.Entities {
		e := entity
		e.Inbound = moveTreesToProcessMap(entity.Inbound, wire.Processes)
		e.Outbound = moveTreesToProcessMap(entity.Outbound, wire.Processes)
		wire.Entities[entityID] = e
	}
	if len(wire.Processes) == 0 {
		wire.Processes = nil // omitempty: don't ship an empty object
	}
	return wire
}

// moveTreesToProcessMap returns a copy of events with their trees lifted into
// processes and the per-event tree cleared.
//
// On collision the DEEPER chain wins. The process-tree cache TTL (1 minute) is
// shorter than the flush interval (2 minutes), so two lookups for one process
// inside a single interval can legitimately return chains with different amounts
// of ancestry resolved. First-wins would discard the richer chain and would make
// the payload depend on Go's randomised map iteration order.
func moveTreesToProcessMap(events map[string]armotypes.NetworkStreamEvent, processes map[armotypes.ProcessRef]*armotypes.ProcessTree) map[string]armotypes.NetworkStreamEvent {
	out := make(map[string]armotypes.NetworkStreamEvent, len(events))
	for key, event := range events {
		// event is a copy of the map value, so clearing its tree below cannot
		// reach the snapshot the channel consumer holds.
		if event.ProcessRef != nil && event.ProcessTree != nil {
			ref := *event.ProcessRef
			existing, seen := processes[ref]
			if !seen || chainDepth(&event.ProcessTree.ProcessTree) > chainDepth(&existing.ProcessTree) {
				processes[ref] = capTreeCopy(event.ProcessTree)
			}
		}
		event.ProcessTree = nil // the wire carries the ref; the tree lives in Processes
		out[key] = event
	}
	return out
}

// capTreeCopy returns an independent copy of a chain with every node's command
// line capped. It must copy rather than cap in place: the nodes are shared with
// the process-tree manager's LRU cache, the legacy alert paths, and the
// notification-channel consumer, all of which keep the uncapped values.
func capTreeCopy(tree *armotypes.ProcessTree) *armotypes.ProcessTree {
	if tree == nil {
		return nil
	}
	copied := copyCappedProcess(&tree.ProcessTree, maxTreeDepth)
	if copied == nil {
		return nil
	}
	// Copy the wrapper wholesale rather than field-listing it: a field list silently
	// drops anything added to ProcessTree later, which is the exact trap the three
	// existing process copiers fell into (see docs/features/process-start-time.md).
	dst := *tree
	dst.ProcessTree = *copied
	return &dst
}

// copyCappedProcess copies a node and its descendants, capping command lines as
// it goes, and writes NOTHING to the source.
//
// armotypes.Process.DeepCopy cannot be used here: it calls MigrateToMap on its
// receiver and on every child it recurses into, which allocates ChildrenMap and
// nils Children on nodes other goroutines are reading. This function normalises
// the deprecated Children slice on read instead.
func copyCappedProcess(src *armotypes.Process, budget int) *armotypes.Process {
	if src == nil || budget <= 0 {
		return nil
	}

	dst := *src // scalar and string fields; strings are immutable, so sharing them is safe
	dst.Cmdline = capCmdline(src.Cmdline)
	dst.Uid = copyUint32Ptr(src.Uid)
	dst.Gid = copyUint32Ptr(src.Gid)
	dst.UpperLayer = copyBoolPtr(src.UpperLayer)
	dst.Children = nil // normalised into ChildrenMap below
	dst.ChildrenMap = nil

	children := make(map[armotypes.CommPID]*armotypes.Process, len(src.ChildrenMap)+len(src.Children))
	for key, child := range src.ChildrenMap {
		if copiedChild := copyCappedProcess(child, budget-1); copiedChild != nil {
			children[key] = copiedChild
		}
	}
	for i := range src.Children {
		copiedChild := copyCappedProcess(&src.Children[i], budget-1)
		if copiedChild == nil {
			continue
		}
		children[armotypes.CommPID{Comm: copiedChild.Comm, PID: copiedChild.PID}] = copiedChild
	}
	if len(children) > 0 {
		dst.ChildrenMap = children
	}
	return &dst
}

func copyUint32Ptr(p *uint32) *uint32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// chainDepth returns the longest root-to-leaf node count, bounded by
// maxTreeDepth. Read-only: unlike DeepCopy it does not normalise as it walks, so
// it counts both child representations.
func chainDepth(node *armotypes.Process) int {
	return chainDepthWithin(node, maxTreeDepth)
}

func chainDepthWithin(node *armotypes.Process, budget int) int {
	if node == nil || budget <= 0 {
		return 0
	}
	deepest := 0
	for _, child := range node.ChildrenMap {
		if d := chainDepthWithin(child, budget-1); d > deepest {
			deepest = d
		}
	}
	for i := range node.Children {
		if d := chainDepthWithin(&node.Children[i], budget-1); d > deepest {
			deepest = d
		}
	}
	return deepest + 1
}

// capCmdline truncates to maxCmdlineBytes including the marker, never splitting a
// UTF-8 rune. Deterministic, so the backend's identity hash is stable for a given
// sensor version.
func capCmdline(cmdline string) string {
	if len(cmdline) <= maxCmdlineBytes {
		return cmdline
	}
	cut := maxCmdlineBytes - len(cmdlineTruncationMarker)
	for cut > 0 && !utf8.RuneStart(cmdline[cut]) {
		cut--
	}
	return cmdline[:cut] + cmdlineTruncationMarker
}
