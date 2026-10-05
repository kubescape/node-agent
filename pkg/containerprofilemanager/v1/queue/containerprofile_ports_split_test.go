package queue

import (
	"context"
	"fmt"
	"net/http"
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

// TestSplitProfileBalancesSkewedNeighborPorts verifies weighted splitting preserves
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
				require.Equal(t, 12, countPartitionableElements(&a.Spec))
				require.Equal(t, 11, countPartitionableElements(&b.Spec))
				require.Equal(t, elementSignatures(&profile.Spec), append(elementSignatures(&a.Spec), elementSignatures(&b.Spec)...))
				aPeers, bPeers := a.Spec.Ingress, b.Spec.Ingress
				if direction == "egress" {
					aPeers, bPeers = a.Spec.Egress, b.Spec.Egress
				}
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
				creator := &portLimitedCreator{}
				q, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: 100})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, q.Close()) })
				profile := testProfile()
				if direction == "ingress" {
					profile.Spec.Ingress = skewedPortNeighbors(heavyIndex)
				} else {
					profile.Spec.Egress = skewedPortNeighbors(heavyIndex)
				}
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
