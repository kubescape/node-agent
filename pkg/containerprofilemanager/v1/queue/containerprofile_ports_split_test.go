package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/DmitriyVTitov/size"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type portLimitedCreator struct{ accepted []*v1beta1.ContainerProfile }

// CreateContainerProfileDirect rejects peers above the port limit and records independent copies of accepted profiles.
func (c *portLimitedCreator) CreateContainerProfileDirect(p *v1beta1.ContainerProfile) error {
	for _, n := range append(append([]v1beta1.NetworkNeighbor{}, p.Spec.Ingress...), p.Spec.Egress...) {
		if len(n.Ports) > 2 {
			return genericStatusError(http.StatusRequestEntityTooLarge)
		}
	}
	c.accepted = append(c.accepted, p.DeepCopy())
	return nil
}

// portSplitNeighbor builds a single peer with enough ports to require successive queue splits.
func portSplitNeighbor() v1beta1.NetworkNeighbor {
	n := v1beta1.NetworkNeighbor{Identifier: "peer", Type: "internal", PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}}
	for i := range 8 {
		n.Ports = append(n.Ports, v1beta1.NetworkPort{Name: fmt.Sprintf("TCP-%d", 8000+i), Protocol: "TCP", Port: new(int32(8000 + i))})
	}
	return n
}

// TestQueueSplitsSingleNeighborPorts verifies HTTP 413 and proactive splits deliver every port with a continuous report chain.
func TestQueueSplitsSingleNeighborPorts(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		for _, proactive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/proactive=%t", direction, proactive), func(t *testing.T) {
				creator := &portLimitedCreator{}
				q, err := NewQueueData(context.Background(), creator, QueueConfig{QueueName: "ports", QueueDir: t.TempDir(), MaxQueueSize: 100, ItemsPerSegment: 10})
				require.NoError(t, err)
				defer q.Close()
				profile := testProfile()
				neighbor := portSplitNeighbor()
				if direction == "ingress" {
					profile.Spec.Ingress = []v1beta1.NetworkNeighbor{neighbor}
				} else {
					profile.Spec.Egress = []v1beta1.NetworkNeighbor{neighbor}
				}
				if proactive {
					require.NoError(t, q.EnqueueWithSizeLimit(profile, "container", int64(size.Of(profile.Spec)-size.Of(neighbor.Ports)/2)))
				} else {
					require.NoError(t, q.Enqueue(profile, "container"))
				}
				for range DefaultMaxSplitDepth + 2 {
					q.processAllItems()
				}
				var ports []v1beta1.NetworkPort
				var rows []tsRow
				for _, p := range creator.accepted {
					peers := p.Spec.Ingress
					if direction == "egress" {
						peers = p.Spec.Egress
					}
					require.Len(t, peers, 1, "must deliver peer data instead of a replacement stitch")
					require.Equal(t, neighbor.Identifier, peers[0].Identifier)
					require.Equal(t, neighbor.PodSelector, peers[0].PodSelector)
					ports = append(ports, peers[0].Ports...)
					rows = append(rows, tsRow{PreviousReportTimestamp: p.Annotations[helpersv1.PreviousReportTimestampMetadataKey], ReportTimestamp: p.Annotations[helpersv1.ReportTimestampMetadataKey]})
				}
				require.ElementsMatch(t, neighbor.Ports, ports)
				assertChainIsLinear(t, rows, profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey], profile.Annotations[helpersv1.ReportTimestampMetadataKey])
				require.Zero(t, q.GetQueueSize())
			})
		}
	}
}

// skewedPortNeighbors places one port-heavy peer among peers with one or no ports.
func skewedPortNeighbors(heavyIndex int) []v1beta1.NetworkNeighbor {
	neighbors := make([]v1beta1.NetworkNeighbor, 16)
	for i := range neighbors {
		neighbors[i] = portSplitNeighbor()
		neighbors[i].Identifier = fmt.Sprintf("peer-%d", i)
		neighbors[i].Ports = neighbors[i].Ports[:i%2]
	}
	neighbors[heavyIndex] = portSplitNeighbor()
	return neighbors
}

// TestSplitProfileBalancesSkewedNeighborPorts verifies byte-balanced splitting preserves
// observation order, zero-port peers, identities, and the unmodified input.
func TestSplitProfileBalancesSkewedNeighborPorts(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		for _, heavyIndex := range []int{0, 8, 15} {
			t.Run(fmt.Sprintf("%s/heavy=%d", direction, heavyIndex), func(t *testing.T) {
				profile := testProfile()
				neighbors := skewedPortNeighbors(heavyIndex)
				if direction == "ingress" {
					profile.Spec.Ingress = neighbors
				} else {
					profile.Spec.Egress = neighbors
				}
				before := profile.DeepCopy()
				a, b, ok := splitProfile(profile)
				require.True(t, ok)
				require.Equal(t, 23, countPartitionableElements(&a.Spec)+countPartitionableElements(&b.Spec))
				require.Equal(t, elementSignatures(&profile.Spec), append(elementSignatures(&a.Spec), elementSignatures(&b.Spec)...))
				aPeers, bPeers := a.Spec.Ingress, b.Spec.Ingress
				if direction == "egress" {
					aPeers, bPeers = a.Spec.Egress, b.Spec.Egress
				}
				encodedParent, err := json.Marshal(neighbors)
				require.NoError(t, err)
				encodedA, err := json.Marshal(aPeers)
				require.NoError(t, err)
				encodedB, err := json.Marshal(bPeers)
				require.NoError(t, err)
				require.LessOrEqual(t, max(len(encodedA), len(encodedB)), 2*len(encodedParent)/3)
				require.LessOrEqual(t, len(aPeers)+len(bPeers), len(neighbors)+1)
				if aPeers[len(aPeers)-1].Identifier == bPeers[0].Identifier {
					// Only a boundary peer is duplicated, with independent identity and ports.
					aPeers[len(aPeers)-1].PodSelector.MatchLabels["app"] = "changed"
					*aPeers[len(aPeers)-1].Ports[0].Port = 1
					require.Equal(t, "api", bPeers[0].PodSelector.MatchLabels["app"])
				}
				require.Equal(t, before, profile)
			})
		}
	}
}

// TestQueueSplitsSkewedNeighborPortsWithinDefaultDepth verifies a heavy peer is
// split before peer isolation exhausts the HTTP 413 retry lineage's depth budget.
func TestQueueSplitsSkewedNeighborPortsWithinDefaultDepth(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		for _, heavyIndex := range []int{0, 8, 15} {
			t.Run(fmt.Sprintf("%s/heavy=%d", direction, heavyIndex), func(t *testing.T) {
				creator := &byteLimitedCreator{}
				q, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: 100})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, q.Close()) })
				profile := testProfile()
				if direction == "ingress" {
					profile.Spec.Ingress = skewedPortNeighbors(heavyIndex)
				} else {
					profile.Spec.Egress = skewedPortNeighbors(heavyIndex)
				}
				limitProfile := testProfile()
				limitedPeer := portSplitNeighbor()
				limitedPeer.Ports = limitedPeer.Ports[:4]
				if direction == "ingress" {
					limitProfile.Spec.Ingress = []v1beta1.NetworkNeighbor{limitedPeer}
				} else {
					limitProfile.Spec.Egress = []v1beta1.NetworkNeighbor{limitedPeer}
				}
				creator.limit = limitProfile.Size()
				require.NoError(t, q.Enqueue(profile, "container"))
				for range DefaultMaxSplitDepth + 2 {
					q.processAllItems()
				}
				var observations []string
				var rows []tsRow
				for _, accepted := range creator.accepted {
					observations = append(observations, elementSignatures(&accepted.Spec)...)
					rows = append(rows, tsRow{PreviousReportTimestamp: accepted.Annotations[helpersv1.PreviousReportTimestampMetadataKey], ReportTimestamp: accepted.Annotations[helpersv1.ReportTimestampMetadataKey]})
				}
				require.ElementsMatch(t, elementSignatures(&profile.Spec), observations)
				assertChainIsLinear(t, rows, profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey], profile.Annotations[helpersv1.ReportTimestampMetadataKey])
				require.Zero(t, q.chunksDropped.Load())
				require.Zero(t, q.GetQueueSize())
			})
		}
	}
}

// byteLimitedCreator models storage's transport rejection using encoded protobuf size.
type byteLimitedCreator struct {
	limit    int
	accepted []*v1beta1.ContainerProfile
}

// CreateContainerProfileDirect rejects oversized wire payloads and records accepted copies.
func (c *byteLimitedCreator) CreateContainerProfileDirect(p *v1beta1.ContainerProfile) error {
	if p.Size() > c.limit {
		return genericStatusError(http.StatusRequestEntityTooLarge)
	}
	c.accepted = append(c.accepted, p.DeepCopy())
	return nil
}

// TestQueueSplitsSelectorHeavyNeighbors verifies numerous large identities are balanced
// even when another peer's large port count would dominate an observation-count cut.
func TestQueueSplitsSelectorHeavyNeighbors(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		t.Run(direction, func(t *testing.T) {
			profile := testProfile()
			heavyPorts := portSplitNeighbor()
			heavyPorts.Ports = nil
			for i := range 512 {
				heavyPorts.Ports = append(heavyPorts.Ports, v1beta1.NetworkPort{Name: fmt.Sprintf("TCP-%d", 8000+i), Protocol: "TCP", Port: new(int32(8000 + i))})
			}
			neighbors := []v1beta1.NetworkNeighbor{heavyPorts}
			for i := range 40 {
				peer := portSplitNeighbor()
				peer.Identifier = fmt.Sprintf("selector-peer-%d", i)
				peer.Ports = peer.Ports[:1]
				for j := range 1500 {
					peer.PodSelector.MatchLabels[fmt.Sprintf("label-%04d", j)] = strings.Repeat("v", 63)
				}
				neighbors = append(neighbors, peer)
			}
			if direction == "ingress" {
				profile.Spec.Ingress = neighbors
			} else {
				profile.Spec.Egress = neighbors
			}
			creator := &byteLimitedCreator{limit: 3 * 1024 * 1024}
			require.Greater(t, profile.Size(), creator.limit)
			q, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: 100})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, q.Close()) })
			require.NoError(t, q.Enqueue(profile, "container"))
			for range DefaultMaxSplitDepth + 2 {
				q.processAllItems()
			}
			var observations []string
			var rows []tsRow
			for _, accepted := range creator.accepted {
				peers := accepted.Spec.Ingress
				if direction == "egress" {
					peers = accepted.Spec.Egress
				}
				for _, peer := range peers {
					var original *v1beta1.NetworkNeighbor
					for i := range neighbors {
						if neighbors[i].Identifier == peer.Identifier {
							original = &neighbors[i]
							break
						}
					}
					require.NotNil(t, original)
					require.Equal(t, *original, peer, "selectors and ports must stay intact")
				}
				observations = append(observations, elementSignatures(&accepted.Spec)...)
				rows = append(rows, tsRow{PreviousReportTimestamp: accepted.Annotations[helpersv1.PreviousReportTimestampMetadataKey], ReportTimestamp: accepted.Annotations[helpersv1.ReportTimestampMetadataKey]})
			}
			require.ElementsMatch(t, elementSignatures(&profile.Spec), observations)
			assertChainIsLinear(t, rows, profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey], profile.Annotations[helpersv1.ReportTimestampMetadataKey])
			require.Zero(t, q.chunksDropped.Load())
			require.Zero(t, q.GetQueueSize())
		})
	}
}

// TestHalveNeighborsAvoidsDuplicatingLargeIdentity verifies that splitting a peer's
// ports is rejected when copying its selector would make the larger half larger.
func TestHalveNeighborsAvoidsDuplicatingLargeIdentity(t *testing.T) {
	heavy := portSplitNeighbor()
	heavy.Ports = heavy.Ports[:2]
	for i := range 40 {
		heavy.PodSelector.MatchLabels[fmt.Sprintf("label-%d", i)] = strings.Repeat("v", 63)
	}
	small := portSplitNeighbor()
	small.Identifier = "small"
	small.Ports = small.Ports[:1]
	a, b := halveNeighbors([]v1beta1.NetworkNeighbor{heavy, small})
	require.Equal(t, []v1beta1.NetworkNeighbor{heavy}, a)
	require.Equal(t, []v1beta1.NetworkNeighbor{small}, b)
}
