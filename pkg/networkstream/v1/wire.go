package networkstream

import (
	"sort"
	"unicode/utf8"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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

// maxProcessTreeBytes budgets the process trees in one message.
//
// This is the bound that keeps a message under the 5 MiB broker limit. It is
// needed because attribution changed what sizes the payload: the batch key now
// splits per process, so the message grows with the number of DISTINCT PROCESSES
// that connected during the interval, and each one contributes a tree. The
// original payload analysis (SUB-7850) modelled bytes per connection at a fixed
// connection count of 283, which is exactly the quantity the key change stops
// holding fixed. Without a bound, a node with heavy short-lived process churn —
// a cron loop shelling out, a CI runner, exec-based probes — can exceed the limit,
// and the whole message is then rejected and dropped: the node loses its entire
// interval of traffic, not just some trees.
//
// A budget in BYTES rather than a tree count, because tree size varies by ~2.5x
// even with the command-line cap (~2 KB median, ~5 KB p90, ~12 KB for a deep chain
// of capped command lines), so no count bounds the payload.
//
// 1.5 MiB of estimated tree bytes ≈ 2.1 MB once the synchronizer envelope's base64
// costs x1.333, leaving room for the connection entries themselves and for the
// 5 MiB ceiling. At p90 tree size that is ~300 trees, above the largest message
// observed in production (283 connections, so at most 283 distinct processes), so
// this is a safety valve rather than a routine limiter. Whether it ever fires is
// deliberately observable: see the warning below.
const maxProcessTreeBytes = 1536 * 1024

// processNodeOverheadBytes approximates the non-string JSON cost of one process
// node — field names, the numeric ids, the RFC-3339 start time and the child map
// key. Deliberately generous: this feeds a budget, so overestimating shrinks the
// payload and underestimating is what risks the limit.
const processNodeOverheadBytes = 200

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
	candidates := make(map[armotypes.ProcessRef]*processCandidate)
	for entityID, entity := range snapshot.Entities {
		e := entity
		e.Inbound = collectTrees(entity.Inbound, candidates)
		e.Outbound = collectTrees(entity.Outbound, candidates)
		wire.Entities[entityID] = e
	}
	wire.Processes = selectProcessTrees(candidates) // nil when empty: omitempty
	return wire
}

// processCandidate is one distinct process seen in a flush, with the best tree
// found for it and what it would cost to ship.
type processCandidate struct {
	ref         armotypes.ProcessRef
	tree        *armotypes.ProcessTree // the SOURCE tree; copied only if selected
	depth       int
	connections int
	estBytes    int
}

// collectTrees returns a copy of events with the per-event tree cleared, gathering
// one candidate per distinct ref.
//
// On collision the DEEPER chain wins. The process-tree cache TTL (1 minute) is
// shorter than the flush interval (2 minutes), so two lookups for one process
// inside a single interval can legitimately return chains with different amounts
// of ancestry resolved. First-wins would discard the richer chain and would make
// the payload depend on Go's randomised map iteration order.
func collectTrees(events map[string]armotypes.NetworkStreamEvent, candidates map[armotypes.ProcessRef]*processCandidate) map[string]armotypes.NetworkStreamEvent {
	out := make(map[string]armotypes.NetworkStreamEvent, len(events))
	for key, event := range events {
		// event is a copy of the map value, so clearing its tree below cannot
		// reach the snapshot the channel consumer holds.
		if event.ProcessRef != nil && event.ProcessTree != nil {
			ref := *event.ProcessRef
			candidate, seen := candidates[ref]
			if !seen {
				candidate = &processCandidate{ref: ref}
				candidates[ref] = candidate
			}
			candidate.connections++
			if depth := chainDepth(&event.ProcessTree.ProcessTree); !seen || depth > candidate.depth {
				candidate.tree = event.ProcessTree
				candidate.depth = depth
				candidate.estBytes = estimateTreeBytes(event.ProcessTree)
			}
		}
		event.ProcessTree = nil // the wire carries the ref; the tree lives in Processes
		out[key] = event
	}
	return out
}

// selectProcessTrees copies the candidate trees that fit maxProcessTreeBytes,
// returning nil when there are none so omitempty drops the field.
//
// Over budget, candidates are ranked by connection count first: a process that
// reached many endpoints is both the most expensive attribution to lose and the
// shape reputation cares about most (beacon-style fan-out). Ties break on the ref
// so the payload never depends on map iteration order. Dropped candidates keep
// their refs on the connections — the pid identity survives, and ProcessTreeFor is
// specified to return nil for a ref with no entry — so the cost is degraded
// attribution for the least-connected processes rather than a rejected message and
// the loss of every traffic row for the interval.
func selectProcessTrees(candidates map[armotypes.ProcessRef]*processCandidate) map[armotypes.ProcessRef]*armotypes.ProcessTree {
	if len(candidates) == 0 {
		return nil
	}

	totalBytes := 0
	for _, candidate := range candidates {
		totalBytes += candidate.estBytes
	}

	processes := make(map[armotypes.ProcessRef]*armotypes.ProcessTree, len(candidates))
	if totalBytes <= maxProcessTreeBytes {
		for ref, candidate := range candidates {
			processes[ref] = capTreeCopy(candidate.tree)
		}
		return processes
	}

	ordered := make([]*processCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.connections != b.connections {
			return a.connections > b.connections
		}
		if a.ref.PID != b.ref.PID {
			return a.ref.PID < b.ref.PID
		}
		return a.ref.StartTimeNs < b.ref.StartTimeNs
	})

	usedBytes, droppedTrees, droppedConnections := 0, 0, 0
	for _, candidate := range ordered {
		// Skip rather than stop, so a small tree still ships after an oversized one.
		if usedBytes+candidate.estBytes > maxProcessTreeBytes {
			droppedTrees++
			droppedConnections += candidate.connections
			continue
		}
		processes[candidate.ref] = capTreeCopy(candidate.tree)
		usedBytes += candidate.estBytes
	}

	// The whole point of the budget is that we find out whether it ever fires.
	logger.L().Warning("NetworkStream - process tree budget exceeded, shipping refs without trees for the least-connected processes",
		helpers.Int("distinctProcesses", len(candidates)),
		helpers.Int("treesShipped", len(processes)),
		helpers.Int("treesDropped", droppedTrees),
		helpers.Int("connectionsWithoutTree", droppedConnections),
		helpers.Int("estimatedTreeBytes", totalBytes),
		helpers.Int("budgetBytes", maxProcessTreeBytes))

	return processes
}

// estimateTreeBytes approximates a tree's serialised size, counting the command
// line as it will be AFTER capping. Read-only, and bounded by maxTreeDepth.
func estimateTreeBytes(tree *armotypes.ProcessTree) int {
	if tree == nil {
		return 0
	}
	return len(tree.ContainerID) + estimateProcessBytes(&tree.ProcessTree, maxTreeDepth)
}

func estimateProcessBytes(node *armotypes.Process, budget int) int {
	if node == nil || budget <= 0 {
		return 0
	}
	total := processNodeOverheadBytes +
		min(len(node.Cmdline), maxCmdlineBytes) +
		len(node.Comm) + len(node.Pcomm) + len(node.Path) + len(node.Cwd) +
		len(node.Hardlink) + len(node.UserName) + len(node.GroupName)
	for _, child := range node.ChildrenMap {
		total += estimateProcessBytes(child, budget-1)
	}
	for i := range node.Children {
		total += estimateProcessBytes(&node.Children[i], budget-1)
	}
	return total
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
