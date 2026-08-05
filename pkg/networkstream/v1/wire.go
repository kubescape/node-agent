package networkstream

import (
	"sort"
	"unicode/utf8"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// Wire-format assembly for the HTTP payload. The reasoning behind every constant
// here, with the production measurements it was calibrated against, is in
// docs/features/network-stream-process-attribution.md.

// maxCmdlineBytes caps a command line on the WIRE COPY ONLY. cmdline is unbounded
// and ~40% of a tree's bytes. The alert paths and the notification-channel consumer
// share these nodes and must keep the full value.
const maxCmdlineBytes = 1024

// cmdlineTruncationMarker makes a cut visible, and is charged against the cap.
const cmdlineTruncationMarker = "…"

// maxTreeDepth bounds every recursive walk here, so a malformed or cyclic tree
// costs a truncated payload rather than the stack. Real chains are ~10 nodes.
const maxTreeDepth = 64

// maxProcessTreeBytes bounds the trees in one message, keeping it under the
// broker's 5 MiB limit. Exceeding that limit is not graceful: the message is
// rejected and dropped, so the node loses its whole interval of traffic rather
// than some trees. A bound is needed because the process-aware batch key makes the
// payload scale with distinct processes, which nothing else limits.
//
// Bytes rather than a tree count, because tree size varies too much for any count
// to bound the payload. 2.5 MiB holds ~461 realistic trees — well above the largest
// batch observed in production (283 connections), so it is a safety valve rather
// than a routine limiter.
const maxProcessTreeBytes = 2560 * 1024

// processNodeOverheadBytes is one node's non-string JSON cost: field names, the
// numeric ids, the always-serialised start time and the childrenMap wrapper.
//
// Measured at ~149 bytes (133 for a node with every numeric at max and strings
// empty, plus ~16 for the childrenMap wrapper). 320 is therefore deliberate
// headroom, not a measurement: it absorbs the fields not modelled individually,
// such as ProcessTree.UniqueID, and anything added to the type later. Per-entry map
// keys are charged explicitly rather than from this slack.
const processNodeOverheadBytes = 320

// processMapKeyOverheadBytes is a childrenMap entry key's cost apart from the comm:
// two quotes, the separator CommPID.MarshalText writes (U+241F, three UTF-8 bytes),
// up to ten digits of pid, and the colon and comma around the entry.
const processMapKeyOverheadBytes = 2 + 3 + 10 + 2

// escapedByteBytes is what one JSON-escaped byte costs. \uXXXX is the worst form;
// the short forms cost 2 but are charged 6 as well, erring toward a smaller payload.
const escapedByteBytes = 6

// buildWireStream derives the HTTP payload from the flush snapshot: each event's
// tree moves into the message-scoped Processes map (one capped copy per distinct
// ref), events keep only their ref, and the version marker is set unconditionally
// so an upgraded sensor with nothing to attribute stays distinguishable from one
// that predates attribution.
//
// Never mutates the snapshot: the notification-channel consumer holds it, and the
// trees are shared with the process-tree cache and the alert paths.
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
// On collision the deeper chain wins: the tree cache TTL is shorter than the flush
// interval, so two lookups for one process can return different amounts of resolved
// ancestry, and first-wins would both discard the richer chain and make the payload
// depend on map iteration order.
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
// Over budget, ranking is smallest-tree-first, which maximises how many processes
// keep a tree; ties break on the ref so the shipped set never depends on map
// iteration order. (Ranking by connection count was rejected: a low-and-slow beacon
// makes one connection per interval, so it would lose its tree first.)
//
// Connections are never dropped — only trees. Their refs stay put, so pid identity
// survives and ProcessTreeFor returns nil for them as specified.
func selectProcessTrees(candidates map[armotypes.ProcessRef]*processCandidate) map[armotypes.ProcessRef]*armotypes.ProcessTree {
	processes, stats := selectWithinBudget(candidates)
	if stats.exceeded {
		// Logged so we learn whether this ever fires in production; these counts are
		// the decision input for raising the budget or making it configurable.
		logger.L().Warning("NetworkStream - process tree budget exceeded, dropping the largest trees",
			helpers.Int("processesWithTrees", stats.candidates),
			helpers.Int("treesShipped", stats.treesShipped),
			helpers.Int("treesDropped", stats.treesDropped),
			helpers.Int("connectionsWithoutTree", stats.connectionsWithoutTree),
			helpers.Int("estimatedTreeBytes", stats.estimatedBytes),
			helpers.Int("budgetBytes", maxProcessTreeBytes))
	}
	return processes
}

// budgetStats reports what a selection did. The drop figures are DERIVED from the
// result rather than accumulated inside the packing loop, so they stay correct
// however that loop is later restructured.
type budgetStats struct {
	candidates             int
	treesShipped           int
	treesDropped           int
	connectionsWithoutTree int
	estimatedBytes         int
	exceeded               bool
}

func selectWithinBudget(candidates map[armotypes.ProcessRef]*processCandidate) (map[armotypes.ProcessRef]*armotypes.ProcessTree, budgetStats) {
	stats := budgetStats{candidates: len(candidates)}
	if len(candidates) == 0 {
		return nil, stats
	}

	totalConnections := 0
	for _, candidate := range candidates {
		stats.estimatedBytes += candidate.estBytes
		totalConnections += candidate.connections
	}

	processes := make(map[armotypes.ProcessRef]*armotypes.ProcessTree, len(candidates))
	if stats.estimatedBytes <= maxProcessTreeBytes {
		for ref, candidate := range candidates {
			processes[ref] = capTreeCopy(candidate.tree)
		}
		stats.treesShipped = len(processes)
		return processes, stats
	}
	stats.exceeded = true

	ordered := make([]*processCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.estBytes != b.estBytes {
			return a.estBytes < b.estBytes
		}
		if a.ref.PID != b.ref.PID {
			return a.ref.PID < b.ref.PID
		}
		return a.ref.StartTimeNs < b.ref.StartTimeNs
	})

	usedBytes, shippedConnections := 0, 0
	for _, candidate := range ordered {
		// Defensive only: the ascending sort means nothing after the first miss can
		// fit either, so this is equivalent to breaking. It costs one comparison and
		// survives a future change to the ordering.
		if usedBytes+candidate.estBytes > maxProcessTreeBytes {
			continue
		}
		processes[candidate.ref] = capTreeCopy(candidate.tree)
		usedBytes += candidate.estBytes
		shippedConnections += candidate.connections
	}

	stats.treesShipped = len(processes)
	stats.treesDropped = len(candidates) - len(processes)
	stats.connectionsWithoutTree = totalConnections - shippedConnections
	return processes, stats
}

// estimateTreeBytes approximates a tree's serialised size, counting the command
// line as it will be AFTER capping. Read-only, and bounded by maxTreeDepth.
func estimateTreeBytes(tree *armotypes.ProcessTree) int {
	if tree == nil {
		return 0
	}
	return processNodeOverheadBytes + escapedLen(tree.ContainerID) +
		estimateProcessBytes(&tree.ProcessTree, maxTreeDepth)
}

func estimateProcessBytes(node *armotypes.Process, budget int) int {
	if node == nil || budget <= 0 {
		return 0
	}

	// Counted as capTreeCopy will leave it; a cut mid-rune only costs more, not less.
	cmdline := node.Cmdline
	if len(cmdline) > maxCmdlineBytes {
		cmdline = cmdline[:maxCmdlineBytes]
	}

	total := processNodeOverheadBytes + len(cmdlineTruncationMarker) +
		escapedLen(cmdline) +
		escapedLen(node.Comm) + escapedLen(node.Pcomm) + escapedLen(node.Path) +
		escapedLen(node.Cwd) + escapedLen(node.Hardlink) +
		escapedLen(node.UserName) + escapedLen(node.GroupName)
	// A child's comm is emitted TWICE: as its own field, and again in this node's
	// childrenMap key. Charging it once let the estimate undercount whenever a comm
	// was escape-heavy enough to outgrow the per-node slack.
	for _, child := range node.ChildrenMap {
		if child == nil {
			continue
		}
		total += processMapKeyOverheadBytes + escapedLen(child.Comm) +
			estimateProcessBytes(child, budget-1)
	}
	for i := range node.Children {
		child := &node.Children[i]
		total += processMapKeyOverheadBytes + escapedLen(child.Comm) +
			estimateProcessBytes(child, budget-1)
	}
	return total
}

// escapedLen returns at least the bytes encoding/json emits for s, excluding the
// quotes. Never use len() here: json escapes `"`, `\`, control bytes and — Marshal
// enables HTML escaping — `<`, `>`, `&`, which command lines are full of, and it
// replaces each invalid UTF-8 byte (argv is raw kernel bytes) with \ufffd. Those
// cost 6 bytes where len() counts 1, which is enough to void the budget entirely.
func escapedLen(s string) int {
	total := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
				total++
			} else {
				total += escapedByteBytes
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			total += escapedByteBytes // one invalid byte -> the 6-byte \ufffd
		case r == '\u2028' || r == '\u2029': // JSON escapes the line/paragraph separators
			total += escapedByteBytes
		default:
			total += size
		}
		i += size
	}
	return total
}

// capTreeCopy returns an independent copy of a chain with every command line capped.
// It must copy rather than cap in place: these nodes are shared with the process-tree
// cache, the alert paths and the channel consumer, which keep the uncapped values.
func capTreeCopy(tree *armotypes.ProcessTree) *armotypes.ProcessTree {
	if tree == nil {
		return nil
	}
	copied := copyCappedProcess(&tree.ProcessTree, maxTreeDepth)
	if copied == nil {
		return nil
	}
	// Wholesale, not field-listed: a field list silently drops anything added to
	// ProcessTree later. See docs/features/process-start-time.md for that trap.
	dst := *tree
	dst.ProcessTree = *copied
	return &dst
}

// copyCappedProcess copies a node and its descendants, capping command lines, and
// writes NOTHING to the source.
//
// Do not replace this with armotypes.Process.DeepCopy: that calls MigrateToMap on
// its receiver and on every child it descends into, writing to nodes other
// goroutines are reading. This normalises the deprecated Children slice on read.
func copyCappedProcess(src *armotypes.Process, budget int) *armotypes.Process {
	if src == nil || budget <= 0 {
		return nil
	}

	dst := *src // strings are immutable, so sharing them is safe
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

// chainDepth returns the longest root-to-leaf node count, bounded by maxTreeDepth.
// Read-only, so it counts both child representations rather than normalising.
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
