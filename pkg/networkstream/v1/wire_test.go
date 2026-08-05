package networkstream

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chain builds a root->...->leaf process chain, the shape buildBranchToShim
// produces: one child per node, ChildrenMap always allocated.
func chain(pids ...uint32) *armotypes.Process {
	var root, prev *armotypes.Process
	for _, pid := range pids {
		node := &armotypes.Process{PID: pid, Comm: "p" + string(rune('0'+pid%10)), ChildrenMap: map[armotypes.CommPID]*armotypes.Process{}}
		if prev == nil {
			root = node
		} else {
			prev.ChildrenMap[armotypes.CommPID{Comm: node.Comm, PID: node.PID}] = node
		}
		prev = node
	}
	return root
}

func treeOf(containerID string, root *armotypes.Process) *armotypes.ProcessTree {
	return &armotypes.ProcessTree{ContainerID: containerID, ProcessTree: *root}
}

func outboundOnly(entityID string, events map[string]armotypes.NetworkStreamEvent) *armotypes.NetworkStream {
	return &armotypes.NetworkStream{Entities: map[string]armotypes.NetworkStreamEntity{
		entityID: {Outbound: events, Inbound: map[string]armotypes.NetworkStreamEvent{}},
	}}
}

// eventPtr returns the address of a map-held event, which ProcessTreeFor needs.
func eventPtr(nsw *armotypes.NetworkStream, entityID, key string) *armotypes.NetworkStreamEvent {
	ev := nsw.Entities[entityID].Outbound[key]
	return &ev
}

func TestBuildWireStream_TreesShipOncePerProcess(t *testing.T) {
	ref101 := &armotypes.ProcessRef{PID: 101, StartTimeNs: 5_000_000_000}
	tree101 := treeOf("c1", &armotypes.Process{PID: 101, Comm: "curl", Cmdline: "curl https://x"})
	snapshot := outboundOnly("c1", map[string]armotypes.NetworkStreamEvent{
		"1.2.3.4/443/TCP/101/5000000000": {IPAddress: "1.2.3.4", Port: 443, ProcessRef: ref101, ProcessTree: tree101},
		"9.9.9.9/53/UDP/101/5000000000":  {IPAddress: "9.9.9.9", Port: 53, ProcessRef: ref101, ProcessTree: tree101},
	})

	wire := buildWireStream(snapshot)

	assert.Equal(t, armotypes.NetworkStreamProcessAttributionV1, wire.ProcessAttributionVersion)
	require.Len(t, wire.Processes, 1, "one tree per process, not per connection — trees dominate the payload")

	got := wire.ProcessTreeFor(eventPtr(wire, "c1", "1.2.3.4/443/TCP/101/5000000000"))
	require.NotNil(t, got, "the supported join must resolve")
	assert.Equal(t, "curl", got.ProcessTree.Comm)
	assert.Equal(t, "c1", got.ContainerID)

	for key, ev := range wire.Entities["c1"].Outbound {
		assert.Nil(t, ev.ProcessTree, "wire events must not inline trees (%s)", key)
		assert.NotNil(t, ev.ProcessRef, "the ref is what the consumer joins on (%s)", key)
	}

	// The snapshot is the channel consumer's view and must be untouched.
	for _, ev := range snapshot.Entities["c1"].Outbound {
		assert.NotNil(t, ev.ProcessTree, "the channel snapshot keeps its trees")
	}
	assert.NotSame(t, tree101, wire.Processes[*ref101], "the map value is a copy, not the shared chain")
}

func TestBuildWireStream_LegacyEventsPassThrough(t *testing.T) {
	snapshot := outboundOnly("c1", map[string]armotypes.NetworkStreamEvent{
		"1.2.3.4/443/TCP": {IPAddress: "1.2.3.4", Port: 443}, // no ref, no tree
	})

	wire := buildWireStream(snapshot)

	assert.Empty(t, wire.Processes, "omitempty: never ship an empty processes object")
	assert.Equal(t, armotypes.NetworkStreamProcessAttributionV1, wire.ProcessAttributionVersion,
		"the marker is a capability signal, set even when nothing was attributable")
	require.Len(t, wire.Entities["c1"].Outbound, 1, "unattributed connections still ship")
}

// TestBuildWireStream_RefWithoutTree: a ref whose tree never resolved still ships.
// It dangles, and ProcessTreeFor is specified to return nil for that — losing the
// ref instead would lose the pid too.
func TestBuildWireStream_RefWithoutTree(t *testing.T) {
	ref := &armotypes.ProcessRef{PID: 303}
	snapshot := outboundOnly("c1", map[string]armotypes.NetworkStreamEvent{
		"5.6.7.8/80/TCP/303/0": {IPAddress: "5.6.7.8", Port: 80, ProcessRef: ref},
	})

	wire := buildWireStream(snapshot)

	assert.Empty(t, wire.Processes)
	ev := eventPtr(wire, "c1", "5.6.7.8/80/TCP/303/0")
	require.NotNil(t, ev.ProcessRef)
	assert.Nil(t, wire.ProcessTreeFor(ev), "a dangling ref resolves to nil, not a panic")
}

// TestBuildWireStream_DeeperChainWins: the tree cache TTL is shorter than the flush
// interval, so two lookups for one process can return different amounts of resolved
// ancestry. First-wins would discard the richer chain and make the payload depend on
// map iteration order.
func TestBuildWireStream_DeeperChainWins(t *testing.T) {
	ref := &armotypes.ProcessRef{PID: 101, StartTimeNs: 5_000_000_000}
	shallow := treeOf("c1", chain(50, 101))
	deep := treeOf("c1", chain(1, 50, 101))

	// Repeated because map iteration order is randomised per range: the outcome
	// must not depend on which entry is visited first.
	for i := 0; i < 32; i++ {
		snapshot := outboundOnly("c1", map[string]armotypes.NetworkStreamEvent{
			"1.2.3.4/443/TCP/101/5000000000": {ProcessRef: ref, ProcessTree: shallow},
			"9.9.9.9/53/UDP/101/5000000000":  {ProcessRef: ref, ProcessTree: deep},
		})
		wire := buildWireStream(snapshot)
		require.Len(t, wire.Processes, 1)
		assert.Equal(t, uint32(1), wire.Processes[*ref].ProcessTree.PID, "the deeper chain's root must win")
	}
}

func TestBuildWireStream_InboundIsAttributedToo(t *testing.T) {
	ref := &armotypes.ProcessRef{PID: 77, StartTimeNs: 1_000_000_000}
	snapshot := &armotypes.NetworkStream{Entities: map[string]armotypes.NetworkStreamEntity{
		"c1": {
			Inbound: map[string]armotypes.NetworkStreamEvent{
				"1.2.3.4/8080/TCP/77/1000000000": {ProcessRef: ref, ProcessTree: treeOf("c1", chain(77))},
			},
			Outbound: map[string]armotypes.NetworkStreamEvent{},
		},
	}}

	wire := buildWireStream(snapshot)

	require.Len(t, wire.Processes, 1)
	for _, ev := range wire.Entities["c1"].Inbound {
		assert.Nil(t, ev.ProcessTree)
		assert.NotNil(t, ev.ProcessRef)
	}
}

// TestBuildWireStream_DoesNotMutateSharedTree pins what makes sharing tree pointers
// into the snapshot safe: the wire copy must not write to the source nodes, which are
// shared with the process-tree cache, the alert paths and the channel consumer. Fails
// if the copy ever regresses to armotypes.Process.DeepCopy, which mutates as it walks.
func TestBuildWireStream_DoesNotMutateSharedTree(t *testing.T) {
	ref := &armotypes.ProcessRef{PID: 101, StartTimeNs: 5_000_000_000}
	// Deliberately in the legacy shape: nil ChildrenMap, ancestry in Children.
	shared := &armotypes.ProcessTree{ContainerID: "c1", ProcessTree: armotypes.Process{
		PID: 50, Comm: "sh",
		Children: []armotypes.Process{{PID: 101, Comm: "curl", Cmdline: "curl https://x"}},
	}}
	snapshot := outboundOnly("c1", map[string]armotypes.NetworkStreamEvent{
		"1.2.3.4/443/TCP/101/5000000000": {ProcessRef: ref, ProcessTree: shared},
	})

	wire := buildWireStream(snapshot)

	assert.Nil(t, shared.ProcessTree.ChildrenMap, "the source's ChildrenMap must not be allocated behind its back")
	require.Len(t, shared.ProcessTree.Children, 1, "the source's Children slice must not be emptied")
	assert.Equal(t, uint32(101), shared.ProcessTree.Children[0].PID)

	// ...and the legacy child must still reach the wire, normalised on read.
	copied := wire.Processes[*ref]
	require.NotNil(t, copied)
	require.Len(t, copied.ProcessTree.ChildrenMap, 1, "a Children-shaped source is normalised into the copy")
	for _, child := range copied.ProcessTree.ChildrenMap {
		assert.Equal(t, uint32(101), child.PID)
	}
}

// TestBuildWireStream_SerializationContract pins the exact cross-repo wire form
// the backend joins on. A sensor-side refactor must not drift from it silently.
func TestBuildWireStream_SerializationContract(t *testing.T) {
	ref := &armotypes.ProcessRef{PID: 101, StartTimeNs: 5_000_000_000}
	snapshot := outboundOnly("c1", map[string]armotypes.NetworkStreamEvent{
		"1.2.3.4/443/TCP/101/5000000000": {
			IPAddress: "1.2.3.4", Port: 443, Protocol: armotypes.NetworkStreamEventProtocolTCP,
			ProcessRef: ref, ProcessTree: treeOf("c1", &armotypes.Process{PID: 101, Comm: "curl"}),
		},
	})

	payload, err := json.Marshal(buildWireStream(snapshot))
	require.NoError(t, err)
	got := string(payload)

	assert.Contains(t, got, `"processRef":"101/5000000000"`, "per-event reference, text-marshalled")
	assert.Contains(t, got, `"processAttributionVersion":1`)
	assert.Contains(t, got, `"processes":{"101/5000000000":`, "message-scoped map keyed by the same text form")

	// Round-trip through the consumer's own join.
	var decoded armotypes.NetworkStream
	require.NoError(t, json.Unmarshal(payload, &decoded))
	ev := decoded.Entities["c1"].Outbound["1.2.3.4/443/TCP/101/5000000000"]
	assert.Nil(t, ev.ProcessTree, "trees ship once in processes, never inline per event")
	resolved := decoded.ProcessTreeFor(&ev)
	require.NotNil(t, resolved, "the ref must resolve after a full marshal/unmarshal round trip")
	assert.Equal(t, "curl", resolved.ProcessTree.Comm)
}

// TestNoTickScaling guards this feature's one silent failure mode: a StartTimeNs
// division still joins correctly inside a message while breaking identity across
// messages. It must run the WHOLE producer path from processRefFor, where the value
// enters — asserting that buildWireStream preserves a correct literal is a tautology.
func TestNoTickScaling(t *testing.T) {
	const startTimeNs = uint64(5_000_000_000) // procfs values are exact multiples of 10^7
	mgr := processtree.NewProcessTreeManagerMock()
	mgr.SetProcessBootTimeNs(101, startTimeNs)
	ns := newTestStream(t, mgr)

	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))
	wire := buildWireStream(snapshotNetworkStream(&ns.networkEventsStorage))

	require.Len(t, wire.Entities[testNodeName].Outbound, 1)
	for key, ev := range wire.Entities[testNodeName].Outbound {
		require.NotNil(t, ev.ProcessRef)
		assert.Equal(t, startTimeNs, ev.ProcessRef.StartTimeNs, "emitted verbatim, never rescaled")
		assert.Equal(t, "1.2.3.4/443/TCP/101/5000000000", key, "the batch key carries the unscaled value too")
	}
	require.Len(t, wire.Processes, 1)
	for gotRef := range wire.Processes {
		assert.Equal(t, startTimeNs, gotRef.StartTimeNs, "the map key must match the event's ref exactly")
	}
}

func TestCapTreeCopy_CmdlineCapped(t *testing.T) {
	long := strings.Repeat("a", 5000)
	src := &armotypes.ProcessTree{ContainerID: "c1", ProcessTree: armotypes.Process{
		PID: 1, Comm: "sh", Cmdline: long,
		ChildrenMap: map[armotypes.CommPID]*armotypes.Process{
			{PID: 2, Comm: "java"}: {PID: 2, Comm: "java", Cmdline: long,
				ChildrenMap: map[armotypes.CommPID]*armotypes.Process{
					{PID: 3, Comm: "sh"}: {PID: 3, Comm: "sh", Cmdline: long},
				}},
		},
	}}

	capped := capTreeCopy(src)

	assert.LessOrEqual(t, len(capped.ProcessTree.Cmdline), maxCmdlineBytes)
	assert.True(t, strings.HasSuffix(capped.ProcessTree.Cmdline, cmdlineTruncationMarker), "truncation must be visible")
	// Every node in the chain, not just the root.
	var walk func(*armotypes.Process, int)
	seen := 0
	walk = func(node *armotypes.Process, depth int) {
		seen++
		assert.LessOrEqual(t, len(node.Cmdline), maxCmdlineBytes, "node at depth %d", depth)
		for _, child := range node.ChildrenMap {
			walk(child, depth+1)
		}
	}
	walk(&capped.ProcessTree, 0)
	assert.Equal(t, 3, seen, "the whole chain is copied, not just the root")

	// The SOURCE is untouched: it is shared with the legacy alert paths and the
	// notification-channel consumer, which keep the uncapped values.
	assert.Len(t, src.ProcessTree.Cmdline, 5000)
	for _, child := range src.ProcessTree.ChildrenMap {
		assert.Len(t, child.Cmdline, 5000)
		for _, grandchild := range child.ChildrenMap {
			assert.Len(t, grandchild.Cmdline, 5000)
		}
	}
}

func TestCapCmdline(t *testing.T) {
	assert.Equal(t, "curl https://x", capCmdline("curl https://x"), "short command lines pass through unmarked")
	assert.Equal(t, "", capCmdline(""))

	exact := strings.Repeat("a", maxCmdlineBytes)
	assert.Equal(t, exact, capCmdline(exact), "exactly at the cap is not truncated")

	over := strings.Repeat("a", maxCmdlineBytes+1)
	assert.LessOrEqual(t, len(capCmdline(over)), maxCmdlineBytes, "the marker is inside the budget")
	assert.True(t, strings.HasSuffix(capCmdline(over), cmdlineTruncationMarker))

	// Truncation never splits a rune.
	multibyte := strings.Repeat("é", maxCmdlineBytes) // 2 bytes per rune
	capped := capCmdline(multibyte)
	assert.LessOrEqual(t, len(capped), maxCmdlineBytes)
	assert.True(t, utf8.ValidString(capped), "a cut mid-rune would emit invalid UTF-8")
}

// bigTree builds a chain whose estimated size is at least sizeBytes, the way a real
// tree gets big: across ~10 ancestor nodes, not one giant command line. A single
// node cannot exceed processNodeOverheadBytes + maxCmdlineBytes, because the cap
// truncates it — so a helper that piles all the bytes into one cmdline silently
// produces a ~1.2 KB tree however large a size it is asked for.
func bigTree(pid uint32, sizeBytes int) *armotypes.ProcessTree {
	const perNode = processNodeOverheadBytes + maxCmdlineBytes
	nodes := (sizeBytes + perNode - 1) / perNode
	if nodes < 1 {
		nodes = 1
	}
	cmdline := strings.Repeat("a", maxCmdlineBytes)

	var root, prev *armotypes.Process
	for i := 0; i < nodes; i++ {
		// The leaf carries the process's own pid; ancestors get synthetic ones.
		nodePID := pid
		if i < nodes-1 {
			nodePID = pid + uint32((i+1)*1_000_000)
		}
		node := &armotypes.Process{PID: nodePID, Comm: "p", Cmdline: cmdline,
			ChildrenMap: map[armotypes.CommPID]*armotypes.Process{}}
		if prev == nil {
			root = node
		} else {
			prev.ChildrenMap[armotypes.CommPID{Comm: node.Comm, PID: node.PID}] = node
		}
		prev = node
	}
	return treeOf("c1", root)
}

// TestBigTree_ReachesRequestedSize keeps the helper honest: every budget test below
// is meaningless if the trees it builds are smaller than they claim.
func TestBigTree_ReachesRequestedSize(t *testing.T) {
	for _, want := range []int{2048, 5222, 7270, 12288} {
		got := estimateTreeBytes(bigTree(1, want))
		assert.GreaterOrEqual(t, got, want, "bigTree(%d) estimated only %d bytes", want, got)
		// A proportional ceiling: the point is that the helper lands near the size it
		// was asked for, not that it matches an exact byte count that shifts whenever
		// per-node accounting changes.
		assert.Less(t, got, want*5/4+processNodeOverheadBytes+maxCmdlineBytes,
			"bigTree(%d) overshot at %d", want, got)
	}
}

// TestBuildWireStream_UnderBudgetShipsEveryTree: the budget is a safety valve, so
// ordinary messages must be untouched by it.
func TestBuildWireStream_UnderBudgetShipsEveryTree(t *testing.T) {
	events := map[string]armotypes.NetworkStreamEvent{}
	for pid := uint32(1); pid <= 200; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		events[fmt.Sprintf("1.2.3.%d/443/TCP/%d/10000000", pid%256, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, 2048)}
	}

	wire := buildWireStream(outboundOnly("c1", events))

	assert.Len(t, wire.Processes, 200, "200 x ~2 KB is well inside the budget")
}

// TestBuildWireStream_OverBudgetDropsTreesNotConnections pins the failure mode the
// budget exists to prevent. Before it, a node with heavy process churn produced a
// message over the broker's 5 MiB limit, which is rejected and dropped — losing the
// node's ENTIRE interval of traffic. Now the connections all still ship; only the
// least-connected processes lose their trees.
func TestBuildWireStream_OverBudgetDropsTreesNotConnections(t *testing.T) {
	events := map[string]armotypes.NetworkStreamEvent{}
	const processes = 4000
	for pid := uint32(1); pid <= processes; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		events[fmt.Sprintf("10.0.%d.%d/443/TCP/%d/10000000", pid/256, pid%256, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, 2048)}
	}
	snapshot := outboundOnly("c1", events)

	wire := buildWireStream(snapshot)

	// Every connection survives, with its ref.
	require.Len(t, wire.Entities["c1"].Outbound, processes, "connections must never be dropped — that is the data loss this whole change fixes")
	for _, ev := range wire.Entities["c1"].Outbound {
		require.NotNil(t, ev.ProcessRef, "the pid identity survives even when the tree does not")
	}

	// Trees are bounded.
	assert.Less(t, len(wire.Processes), processes, "the budget must actually drop trees")
	assert.NotEmpty(t, wire.Processes, "it must not drop everything either")
	shipped := 0
	for _, tree := range wire.Processes {
		shipped += estimateTreeBytes(tree)
	}
	assert.LessOrEqual(t, shipped, maxProcessTreeBytes, "shipped trees must fit the budget")

	// A dropped ref resolves to nil rather than panicking.
	for _, ev := range wire.Entities["c1"].Outbound {
		_ = wire.ProcessTreeFor(&ev)
	}

	// And the payload stays under the broker limit even after the base64 envelope.
	payload, err := json.Marshal(wire)
	require.NoError(t, err)
	encoded := len(payload) * 4 / 3
	assert.Less(t, encoded, 5<<20, "the whole point: %d bytes JSON -> ~%d base64, under 5 MiB", len(payload), encoded)
}

// TestSelectProcessTrees_IsDeterministic pins the stated contract that the shipped
// SET never depends on Go's randomised map iteration order. Asserting only that one
// particular process survived is not enough: with the ref tie-breaks removed, every
// equal-cost candidate ties, sort.Slice's output becomes iteration-dependent, and
// the set silently varies run to run.
func TestSelectProcessTrees_IsDeterministic(t *testing.T) {
	build := func() map[armotypes.ProcessRef]*armotypes.ProcessTree {
		events := map[string]armotypes.NetworkStreamEvent{}
		for pid := uint32(1); pid <= 2000; pid++ {
			ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
			events[fmt.Sprintf("10.2.%d.%d/443/TCP/%d/10000000", pid/256, pid%256, pid)] =
				armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, 4096)}
		}
		return buildWireStream(outboundOnly("c1", events)).Processes
	}

	first := build()
	require.NotEmpty(t, first)
	require.Less(t, len(first), 2000, "this case must actually exceed the budget")

	firstRefs := make([]string, 0, len(first))
	for ref := range first {
		firstRefs = append(firstRefs, ref.String())
	}
	sort.Strings(firstRefs)

	for i := 0; i < 12; i++ {
		again := build()
		refs := make([]string, 0, len(again))
		for ref := range again {
			refs = append(refs, ref.String())
		}
		sort.Strings(refs)
		require.Equal(t, firstRefs, refs, "the shipped set must be identical on every run")
	}
}

// TestSelectProcessTrees_PrefersSmallestTrees: over budget, ranking is smallest-tree
// first, so the number of processes keeping attribution is maximised. Ranking by
// connection count was rejected — a low-and-slow beacon makes one connection, so it
// would sort last and lose its tree first.
func TestSelectProcessTrees_PrefersSmallestTrees(t *testing.T) {
	small := armotypes.ProcessRef{PID: 1, StartTimeNs: 10_000_000}
	events := map[string]armotypes.NetworkStreamEvent{
		// One connection, tiny tree: the low-and-slow shape. Must survive.
		"10.9.9.9/443/TCP/1/10000000": {ProcessRef: &small, ProcessTree: bigTree(1, 1024)},
	}
	// Chatty processes with large trees that together blow the budget.
	for pid := uint32(100); pid < 1100; pid++ {
		for c := 0; c < 5; c++ {
			ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
			events[fmt.Sprintf("10.3.%d.%d/%d/TCP/%d/10000000", pid/256, pid%256, c, pid)] =
				armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, 12288)}
		}
	}

	wire := buildWireStream(outboundOnly("c1", events))

	require.Less(t, len(wire.Processes), 1001, "this case must exceed the budget")
	assert.NotNil(t, wire.Processes[small],
		"the single-connection process with the smallest tree must keep it — that is the beacon shape")
}

// TestSelectProcessTrees_OversizedTreeIsExcluded: a tree larger than the whole budget
// must be dropped while the rest still ship. Note what this does NOT prove: it passes
// under either loop shape, because the ascending sort puts the small trees first — the
// skip-vs-break branch is unreachable, not load-bearing. Such a tree also has to be
// WIDE, since maxTreeDepth caps a chain at 64 nodes, so real chains never hit this.
func TestSelectProcessTrees_OversizedTreeIsExcluded(t *testing.T) {
	huge := armotypes.ProcessRef{PID: 1, StartTimeNs: 10_000_000}
	oversized := &armotypes.Process{PID: 1, Comm: "p", ChildrenMap: map[armotypes.CommPID]*armotypes.Process{}}
	for i := 0; i < 4000; i++ {
		child := &armotypes.Process{PID: uint32(10_000 + i), Comm: "p",
			Cmdline: strings.Repeat("a", maxCmdlineBytes), ChildrenMap: map[armotypes.CommPID]*armotypes.Process{}}
		oversized.ChildrenMap[armotypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	}
	require.Greater(t, estimateTreeBytes(treeOf("c1", oversized)), maxProcessTreeBytes,
		"this tree must exceed the whole budget on its own")

	events := map[string]armotypes.NetworkStreamEvent{
		"10.9.9.9/443/TCP/1/10000000": {ProcessRef: &huge, ProcessTree: treeOf("c1", oversized)},
	}
	for pid := uint32(2); pid <= 6; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		events[fmt.Sprintf("10.4.0.%d/443/TCP/%d/10000000", pid, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, 2048)}
	}

	wire := buildWireStream(outboundOnly("c1", events))

	assert.Nil(t, wire.Processes[huge], "a tree larger than the whole budget cannot ship")
	assert.Len(t, wire.Processes, 5, "the small trees after it must still ship")
}

// TestEstimateTreeBytes_CountsLegacyChildren: the deprecated Children slice reaches
// the wire (capTreeCopy normalises it into ChildrenMap), so the estimator must charge
// for it. If it did not, a Children-shaped tree would be free against the budget.
func TestEstimateTreeBytes_CountsLegacyChildren(t *testing.T) {
	childless := treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh"})
	withLegacyChild := treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh",
		Children: []armotypes.Process{{PID: 2, Comm: "curl", Cmdline: strings.Repeat("a", 500)}}})

	assert.Greater(t, estimateTreeBytes(withLegacyChild), estimateTreeBytes(childless)+500,
		"a Children-shaped descendant must be charged, not free")
}

// TestCapTreeCopy_PreservesWrapperFields: the wrapper is copied wholesale rather than
// field-listed, so a field added to ProcessTree later cannot be silently dropped.
func TestCapTreeCopy_PreservesWrapperFields(t *testing.T) {
	src := &armotypes.ProcessTree{ContainerID: "c1", UniqueID: 4242,
		ProcessTree: armotypes.Process{PID: 1, Comm: "sh"}}

	capped := capTreeCopy(src)

	assert.Equal(t, "c1", capped.ContainerID)
	assert.Equal(t, uint32(4242), capped.UniqueID, "field-listing the wrapper would drop this")
}

func TestEstimateTreeBytes_CountsCappedCmdline(t *testing.T) {
	assert.Zero(t, estimateTreeBytes(nil))

	short := treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh", Cmdline: "sh -c true"})
	assert.Greater(t, estimateTreeBytes(short), processNodeOverheadBytes)

	// A 200 KB command line must be counted at its CAPPED size, not its raw size —
	// otherwise the budget would reject trees that are small on the wire. Asserted
	// against the raw length rather than a tight constant, so the bound states the
	// intent and does not have to be retuned whenever per-node accounting changes.
	huge := treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh", Cmdline: strings.Repeat("a", 200_000)})
	estimate := estimateTreeBytes(huge)
	assert.Greater(t, estimate, maxCmdlineBytes, "the capped command line is still counted")
	assert.Less(t, estimate, 4*maxCmdlineBytes, "but nothing close to the 200 KB raw length")
}

// TestBuildWireStream_ObservedWorstCaseFitsBudget pins the CALIBRATION, not the
// mechanism: the budget must not bind on traffic production actually produces, or it
// degrades attribution on the busiest nodes. The scenario is the largest batch ever
// observed (283 connections, SUB-7850) with every connection from a distinct process.
// A 1.5 MiB budget fails this, which is why it is 2.5 MiB.
func TestBuildWireStream_ObservedWorstCaseFitsBudget(t *testing.T) {
	const (
		observedWorstConnections = 283
		p90TreeBytes             = 7270
		bytesPerConnection       = 530
	)
	events := map[string]armotypes.NetworkStreamEvent{}
	for pid := uint32(1); pid <= observedWorstConnections; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		events[fmt.Sprintf("10.0.%d.%d/443/TCP/%d/10000000", pid/256, pid%256, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, p90TreeBytes)}
	}

	wire := buildWireStream(outboundOnly("c1", events))

	require.Len(t, wire.Processes, observedWorstConnections,
		"the budget must not bind on the largest batch observed in production")

	// And that case must sit well under the broker limit once base64 applies.
	payload, err := json.Marshal(wire)
	require.NoError(t, err)
	encoded := (len(payload) + observedWorstConnections*bytesPerConnection) * 4 / 3
	assert.Less(t, encoded, 4<<20, "~%d B encoded should stay well clear of the 5 MiB limit", encoded)
}

// realisticNode is a process node shaped the way the tree builder actually
// produces them: every field populated. Sparse nodes are a test artefact.
func realisticNode(pid uint32, cmdline string) *armotypes.Process {
	uid, gid := uint32(1000), uint32(1000)
	upper := true
	return &armotypes.Process{
		PID: pid, PPID: pid - 1, Comm: "some-process", Pcomm: "parent-process",
		Cmdline: cmdline, Path: "/usr/local/bin/some-process", Cwd: "/var/lib/some-process",
		Hardlink: "/usr/local/bin/some-process", UserName: "serviceaccount", GroupName: "serviceaccount",
		Uid: &uid, Gid: &gid, UpperLayer: &upper, StartTime: time.Unix(1754290000, 994619533),
		ChildrenMap: map[armotypes.CommPID]*armotypes.Process{},
	}
}

// escapeHeavyComm is 15 bytes — the kernel's TASK_COMM_LEN bound — of a character
// JSON expands to 6 bytes, so escapedLen is 90 against a len of 15.
const escapeHeavyComm = "<<<<<<<<<<<<<<<"

func escapeHeavyCommTree(children int) *armotypes.ProcessTree {
	root := realisticNode(1, "sh")
	for i := 0; i < children; i++ {
		child := realisticNode(uint32(1000+i), "/usr/bin/curl https://example.com")
		child.Comm = escapeHeavyComm
		root.ChildrenMap[armotypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	}
	return treeOf("c1", root)
}

func escapeHeavyCommLegacyTree(children int) *armotypes.ProcessTree {
	root := realisticNode(1, "sh")
	for i := 0; i < children; i++ {
		child := realisticNode(uint32(1000+i), "/usr/bin/curl https://example.com")
		child.Comm = escapeHeavyComm
		root.Children = append(root.Children, *child)
	}
	return treeOf("c1", root)
}

func unboundedCommTree(children, commBytes int) *armotypes.ProcessTree {
	root := realisticNode(1, "sh")
	for i := 0; i < children; i++ {
		child := realisticNode(uint32(1000+i), "/usr/bin/curl https://example.com")
		child.Comm = strings.Repeat("<", commBytes)
		root.ChildrenMap[armotypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	}
	return treeOf("c1", root)
}

func unboundedCommLegacyTree(children, commBytes int) *armotypes.ProcessTree {
	root := realisticNode(1, "sh")
	for i := 0; i < children; i++ {
		child := realisticNode(uint32(1000+i), "/usr/bin/curl https://example.com")
		child.Comm = strings.Repeat("<", commBytes)
		root.Children = append(root.Children, *child)
	}
	return treeOf("c1", root)
}

func escapeHeavyCommChain(nodes int) *armotypes.ProcessTree {
	var root, prev *armotypes.Process
	for i := 0; i < nodes; i++ {
		node := realisticNode(uint32(100+i), "/usr/bin/curl https://example.com")
		node.Comm = escapeHeavyComm
		if prev == nil {
			root = node
		} else {
			prev.ChildrenMap[armotypes.CommPID{Comm: node.Comm, PID: node.PID}] = node
		}
		prev = node
	}
	return treeOf("c1", root)
}

// TestEstimateTreeBytes_NeverUnderestimates is the guard the budget rests on: if the
// estimate can undercount the marshalled size, maxProcessTreeBytes is not a bound and
// an oversized message ships silently. The subtle case is JSON escaping — see
// escapedLen.
func TestEstimateTreeBytes_NeverUnderestimates(t *testing.T) {
	deepChain := func(nodes int, cmdline string) *armotypes.Process {
		var root, prev *armotypes.Process
		for i := 0; i < nodes; i++ {
			node := realisticNode(uint32(100+i), cmdline)
			if prev == nil {
				root = node
			} else {
				prev.ChildrenMap[armotypes.CommPID{Comm: node.Comm, PID: node.PID}] = node
			}
			prev = node
		}
		return root
	}
	wide := realisticNode(1, "sh")
	for i := 0; i < 50; i++ {
		child := realisticNode(uint32(1000+i), "worker --shard=<n> & echo \"done\"")
		wide.ChildrenMap[armotypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	}

	cases := []struct {
		name string
		tree *armotypes.ProcessTree
	}{
		{"bare", treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh"})},
		{"realistic single node", treeOf("c1", realisticNode(1, "/usr/bin/curl https://example.com/api?a=1"))},
		{"realistic 10-node chain", treeOf("c1", deepChain(10, "/usr/bin/curl https://example.com"))},
		{"realistic 64-node chain", treeOf("c1", deepChain(64, "/usr/bin/curl https://example.com"))},
		{"over-deep chain (truncated)", treeOf("c1", deepChain(120, "sh -c true"))},
		{"wide fan-out", treeOf("c1", wide)},
		// Shell redirects and job control: every < > & costs 6 bytes, not 1.
		{"html-escaped shell cmdline", treeOf("c1", realisticNode(1, strings.Repeat("sh -c 'a > b 2>&1 && c < d' ", 40)))},
		{"all quotes", treeOf("c1", realisticNode(1, strings.Repeat(`"`, 900)))},
		{"all backslashes", treeOf("c1", realisticNode(1, strings.Repeat(`\`, 900)))},
		{"control bytes", treeOf("c1", realisticNode(1, strings.Repeat("\x01\x02\x1f", 300)))},
		// Non-UTF-8 argv: each invalid byte becomes the 6-byte �.
		{"invalid utf-8 argv", treeOf("c1", realisticNode(1, strings.Repeat("\x80", 1024)))},
		{"invalid utf-8 over the cap", treeOf("c1", realisticNode(1, strings.Repeat("\xff", 8000)))},
		{"line separators", treeOf("c1", realisticNode(1, strings.Repeat("a b ", 300)))},
		{"uncapped path field", treeOf("c1", &armotypes.Process{PID: 1, Comm: "x",
			Path: strings.Repeat("\x80", 20_000), Cwd: strings.Repeat("&", 20_000)})},
		{"legacy Children shape", treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh",
			Children: []armotypes.Process{*realisticNode(2, strings.Repeat("<&>", 400))}})},
		// A child's comm is emitted TWICE — as its own field and inside the parent's
		// childrenMap key — so it must be charged twice. At the kernel's 15-byte comm
		// bound the per-node slack happens to absorb the difference, so these cases
		// are regression cover for the near-break-even region...
		{"escape-heavy child comm, fan-out 5", escapeHeavyCommTree(5)},
		{"escape-heavy child comm, fan-out 200", escapeHeavyCommTree(200)},
		{"escape-heavy child comm, legacy Children", escapeHeavyCommLegacyTree(50)},
		{"escape-heavy child comm, 64-node chain", escapeHeavyCommChain(64)},
		// ...and these are the cases that actually discriminate. Nothing in this repo
		// enforces a comm length — it is only ever 15 bytes because every source is a
		// kernel TASK_COMM_LEN buffer. The estimate must not depend on that: with an
		// unbounded comm the old accounting ran ~48% under, and a bound that rests on
		// an unenforced external invariant is not a bound.
		{"unbounded child comm, fan-out 200", unboundedCommTree(200, 1024)},
		{"unbounded child comm, legacy Children", unboundedCommLegacyTree(200, 1024)},
		// containerID lives on the wrapper and is escaped like any other string.
		{"escape-heavy containerID", treeOf(strings.Repeat("<", 64), realisticNode(1, "sh"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Compare against what actually goes on the wire: the capped copy.
			capped := capTreeCopy(tc.tree)
			payload, err := json.Marshal(capped)
			require.NoError(t, err)
			est := estimateTreeBytes(tc.tree)

			assert.GreaterOrEqual(t, est, len(payload),
				"estimate %d < marshalled %d: the budget would not bound the payload", est, len(payload))
		})
	}
}

// TestBuildWireStream_EscapeHeavyPayloadStaysUnderLimit is the end-to-end version:
// many processes whose command lines are non-UTF-8 kernel bytes, which inflate 6x
// through JSON. Before escaping was accounted for, 629 such processes estimated at
// 29% of the budget and produced 5.37 MB after base64 — over the broker limit, with
// nothing dropped and nothing logged.
func TestBuildWireStream_EscapeHeavyPayloadStaysUnderLimit(t *testing.T) {
	events := map[string]armotypes.NetworkStreamEvent{}
	for pid := uint32(1); pid <= 800; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		events[fmt.Sprintf("10.%d.%d.%d/443/TCP/%d/10000000", pid/65536, pid/256%256, pid%256, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref,
				ProcessTree: treeOf("c1", realisticNode(pid, strings.Repeat("\x80", maxCmdlineBytes)))}
	}

	wire := buildWireStream(outboundOnly("c1", events))

	payload, err := json.Marshal(wire)
	require.NoError(t, err)
	encoded := len(payload) * 4 / 3
	assert.Less(t, encoded, 5<<20,
		"%d processes -> %d B JSON -> ~%d B base64, must stay under the 5 MiB broker limit",
		len(wire.Processes), len(payload), encoded)
	require.Len(t, wire.Entities["c1"].Outbound, 800, "connections are never dropped")
}

// TestEstimateTreeBytes_NeverUnderestimatesRandom is the generalisation of the
// table above: the budget's soundness depends on a property that must hold for
// ALL inputs, and process argv is arbitrary kernel bytes. Deterministic seed, so a
// failure is reproducible.
func TestEstimateTreeBytes_NeverUnderestimatesRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(20260804))
	randomBytes := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			switch rng.Intn(5) {
			case 0: // the bytes JSON escapes to 6 chars
				b[i] = []byte{'<', '>', '&', 0x00, 0x1f}[rng.Intn(5)]
			case 1: // the short escapes
				b[i] = []byte{'"', '\\', '\n', '\r', '\t'}[rng.Intn(5)]
			case 2: // high bytes: mostly invalid UTF-8
				b[i] = byte(0x80 + rng.Intn(0x80))
			default: // plain ASCII
				b[i] = byte(0x20 + rng.Intn(0x5f))
			}
		}
		return string(b)
	}

	for i := 0; i < 400; i++ {
		node := &armotypes.Process{
			PID: uint32(rng.Intn(1 << 20)), PPID: uint32(rng.Intn(1 << 20)),
			Comm: randomBytes(rng.Intn(24)), Pcomm: randomBytes(rng.Intn(24)),
			Cmdline: randomBytes(rng.Intn(3000)), Path: randomBytes(rng.Intn(300)),
			Cwd: randomBytes(rng.Intn(300)), Hardlink: randomBytes(rng.Intn(60)),
			UserName: randomBytes(rng.Intn(30)), GroupName: randomBytes(rng.Intn(30)),
			ChildrenMap: map[armotypes.CommPID]*armotypes.Process{},
		}
		// Children are FULLY populated, and comms are drawn at the kernel's 15-byte
		// bound from the escape-heavy alphabet. A previous generator set only four
		// fields per child, which left the per-node slack untouched and could never
		// reach the deficit region where the childrenMap key made the estimate
		// undercount — 200k trees found nothing.
		//
		// Draw the child count ONCE: in the loop condition it is redrawn per iteration,
		// which skews the distribution badly (5 children becomes ~1.5% likely instead of
		// ~16.7%) and starves the high-fan-out cases this generator exists to reach.
		children := rng.Intn(6)
		for c := 0; c < children; c++ {
			uid, gid := uint32(rng.Intn(70000)), uint32(rng.Intn(70000))
			upper := rng.Intn(2) == 0
			child := &armotypes.Process{
				PID: uint32(rng.Intn(1 << 20)), PPID: uint32(rng.Intn(1 << 20)),
				Comm: escapeHeavyBytes(rng, 15), Pcomm: escapeHeavyBytes(rng, 15),
				Cmdline: randomBytes(rng.Intn(2000)), Path: randomBytes(rng.Intn(200)),
				Cwd: randomBytes(rng.Intn(200)), Hardlink: randomBytes(rng.Intn(60)),
				UserName: randomBytes(rng.Intn(30)), GroupName: randomBytes(rng.Intn(30)),
				Uid: &uid, Gid: &gid, UpperLayer: &upper,
				StartTime:   time.Unix(int64(1754290000+rng.Intn(1000)), int64(rng.Intn(1e9))),
				ChildrenMap: map[armotypes.CommPID]*armotypes.Process{},
			}
			node.ChildrenMap[armotypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
		}
		tree := treeOf(randomBytes(rng.Intn(40)), node)

		payload, err := json.Marshal(capTreeCopy(tree))
		require.NoError(t, err)
		est := estimateTreeBytes(tree)
		require.GreaterOrEqual(t, est, len(payload),
			"iteration %d: estimate %d < marshalled %d — the budget would not bound the payload", i, est, len(payload))
	}
}

// escapeHeavyBytes builds a string of n bytes weighted heavily toward characters
// JSON expands to six bytes, which is the region where a len()-based estimate
// undercounts the marshalled size.
func escapeHeavyBytes(rng *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		if rng.Intn(4) == 0 {
			b[i] = byte(0x20 + rng.Intn(0x5f)) // plain ASCII
			continue
		}
		b[i] = []byte{'<', '>', '&', '"', '\\', 0x01, 0x1f, 0x80, 0xff}[rng.Intn(9)]
	}
	return string(b)
}

// TestSelectProcessTrees_MaximisesTreesKept pins the ranking ORDER, which
// TestSelectProcessTrees_PrefersSmallestTrees does not: every tree there is the same
// size, so ordering only decides which equal-sized trees ship. Mixing two size
// populations makes the shipped COUNT depend on the order, which is the property
// smallest-first exists for.
func TestSelectProcessTrees_MaximisesTreesKept(t *testing.T) {
	const smallBytes, largeBytes = 20_000, 80_000
	smallEst := estimateTreeBytes(bigTree(1, smallBytes))
	require.Greater(t, estimateTreeBytes(bigTree(1, largeBytes)), smallEst*3,
		"the two populations must be far enough apart to discriminate")

	events := map[string]armotypes.NetworkStreamEvent{}
	smallRefs := map[armotypes.ProcessRef]bool{}
	for pid := uint32(1); pid <= 200; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		smallRefs[*ref] = true
		events[fmt.Sprintf("10.1.0.%d/443/TCP/%d/10000000", pid%256, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, smallBytes)}
	}
	for pid := uint32(1000); pid < 1100; pid++ {
		ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
		events[fmt.Sprintf("10.2.0.%d/443/TCP/%d/10000000", pid%256, pid)] =
			armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, largeBytes)}
	}

	wire := buildWireStream(outboundOnly("c1", events))

	// Greedy-smallest is optimal for "most processes keep a tree", so the expected
	// count is computable rather than a magic number.
	want := min(maxProcessTreeBytes/smallEst, 200)
	assert.Equal(t, want, len(wire.Processes), "ranking must maximise how many processes keep a tree")
	for ref := range wire.Processes {
		assert.True(t, smallRefs[ref], "a large tree displaced a small one: ranking is not smallest-first")
	}
}

// TestSelectWithinBudget_StatsAreDerived pins the counters the budget warning reports.
// They are the decision input for whether the budget needs raising, so they must be
// consistent by construction rather than by an accumulator that a future change to the
// packing loop could silently desynchronise.
func TestSelectWithinBudget_StatsAreDerived(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		processes, stats := selectWithinBudget(nil)
		assert.Nil(t, processes, "nil so omitempty drops the field")
		assert.False(t, stats.exceeded)
		assert.Zero(t, stats.candidates)
	})

	build := func(count, sizeBytes, connsEach int) map[armotypes.ProcessRef]*processCandidate {
		candidates := map[armotypes.ProcessRef]*processCandidate{}
		for pid := uint32(1); pid <= uint32(count); pid++ {
			ref := armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
			tree := bigTree(pid, sizeBytes)
			candidates[ref] = &processCandidate{
				ref: ref, tree: tree, connections: connsEach, estBytes: estimateTreeBytes(tree),
			}
		}
		return candidates
	}

	t.Run("under budget", func(t *testing.T) {
		candidates := build(20, 2048, 3)
		processes, stats := selectWithinBudget(candidates)
		assert.False(t, stats.exceeded)
		assert.Len(t, processes, 20)
		assert.Equal(t, 20, stats.treesShipped)
		assert.Zero(t, stats.treesDropped)
		assert.Zero(t, stats.connectionsWithoutTree)
	})

	t.Run("over budget", func(t *testing.T) {
		const count, connsEach = 1000, 4
		candidates := build(count, 12288, connsEach)
		processes, stats := selectWithinBudget(candidates)

		require.True(t, stats.exceeded, "this case must exceed the budget")
		assert.Equal(t, count, stats.candidates)
		assert.Equal(t, len(processes), stats.treesShipped)
		// The identities that hold however the loop is written.
		assert.Equal(t, count, stats.treesShipped+stats.treesDropped,
			"every candidate is either shipped or counted as dropped")
		assert.Equal(t, stats.treesDropped*connsEach, stats.connectionsWithoutTree,
			"connections without a tree must follow from the trees actually dropped")
		assert.Greater(t, stats.estimatedBytes, maxProcessTreeBytes)
	})
}
