package networkstream

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
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

// TestBuildWireStream_DeeperChainWins: the process-tree cache TTL (1 min) is
// shorter than the flush interval (2 min), so two lookups for one process inside
// a single interval can legitimately return chains with different amounts of
// ancestry resolved. First-wins would discard the richer chain and would make the
// payload depend on Go's map iteration order; preferring the deeper chain is
// deterministic.
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

// TestBuildWireStream_DoesNotMutateSharedTree pins the constraint that makes
// sharing tree pointers into the flush snapshot safe: the wire copy must not
// write to the source nodes. They are shared with the process-tree manager's LRU
// cache, the legacy alert paths, and the notification-channel consumer.
//
// armotypes.Process.DeepCopy is NOT usable for this: it calls MigrateToMap on its
// receiver and on every child it recurses into, which allocates ChildrenMap and
// nils Children on the SHARED nodes. This test fails if the copy ever regresses
// to it.
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

// TestNoTickScaling guards the one silent failure mode of this feature: a
// StartTimeNs division would still join correctly inside a single message — the key
// and the ref share a producer — while breaking identity across messages by seven
// orders of magnitude.
//
// It must run the WHOLE producer path, starting at processRefFor where the value
// enters, because that is where a scaling bug would be introduced. Asserting only
// that buildWireStream does not rewrite an already-correct literal is a tautology.
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
		assert.Less(t, got, want+processNodeOverheadBytes+maxCmdlineBytes, "bigTree(%d) overshot at %d", want, got)
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

// TestSelectProcessTrees_PrefersFanOutDeterministically: over budget, the process
// that reached the most endpoints keeps its tree, and the outcome must not depend
// on Go's randomised map iteration order.
func TestSelectProcessTrees_PrefersFanOutDeterministically(t *testing.T) {
	chatty := armotypes.ProcessRef{PID: 900, StartTimeNs: 10_000_000}
	for i := 0; i < 16; i++ {
		events := map[string]armotypes.NetworkStreamEvent{}
		// One process with many connections...
		for c := 0; c < 40; c++ {
			ref := chatty
			events[fmt.Sprintf("10.1.1.%d/443/TCP/900/10000000", c)] =
				armotypes.NetworkStreamEvent{ProcessRef: &ref, ProcessTree: bigTree(900, 4096)}
		}
		// ...and many single-connection processes that together blow the budget.
		for pid := uint32(1); pid <= 2000; pid++ {
			ref := &armotypes.ProcessRef{PID: pid, StartTimeNs: 10_000_000}
			events[fmt.Sprintf("10.2.%d.%d/443/TCP/%d/10000000", pid/256, pid%256, pid)] =
				armotypes.NetworkStreamEvent{ProcessRef: ref, ProcessTree: bigTree(pid, 4096)}
		}

		wire := buildWireStream(outboundOnly("c1", events))

		require.NotNil(t, wire.Processes[chatty], "the highest-fan-out process must keep its tree on every run")
	}
}

func TestEstimateTreeBytes_CountsCappedCmdline(t *testing.T) {
	assert.Zero(t, estimateTreeBytes(nil))

	short := treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh", Cmdline: "sh -c true"})
	assert.Greater(t, estimateTreeBytes(short), processNodeOverheadBytes)

	// A 200 KB command line must be counted as its capped size, not its raw size —
	// otherwise the budget would reject trees that are actually small on the wire.
	huge := treeOf("c1", &armotypes.Process{PID: 1, Comm: "sh", Cmdline: strings.Repeat("a", 200_000)})
	assert.Less(t, estimateTreeBytes(huge), processNodeOverheadBytes+maxCmdlineBytes+64)
}

// TestBuildWireStream_ObservedWorstCaseFitsBudget pins the CALIBRATION, not just
// the mechanism. The budget must not bind on traffic that production actually
// produces, or it degrades attribution on exactly the busiest nodes.
//
// The scenario is the worst case the budget exists for, at the largest batch ever
// observed: 283 connections (SUB-7850), every one from a DISTINCT process, each
// carrying a p90-sized (~7 KB) tree. Measured production inputs: a batch averages
// ~42 connections at ~530 bytes of JSON each (prod-eu, reputation events_in over
// topic message count, against a 29 KB mean message).
//
// A 1.5 MiB budget fails this test — it binds at 216 trees — which is why the
// budget is 2.5 MiB.
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
