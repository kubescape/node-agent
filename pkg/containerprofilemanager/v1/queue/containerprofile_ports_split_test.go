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

func (c *portLimitedCreator) CreateContainerProfileDirect(p *v1beta1.ContainerProfile) error {
	for _, n := range append(append([]v1beta1.NetworkNeighbor{}, p.Spec.Ingress...), p.Spec.Egress...) {
		if len(n.Ports) > 2 {
			return genericStatusError(http.StatusRequestEntityTooLarge)
		}
	}
	c.accepted = append(c.accepted, p.DeepCopy())
	return nil
}

func portSplitNeighbor() v1beta1.NetworkNeighbor {
	n := v1beta1.NetworkNeighbor{Identifier: "peer", Type: "internal", PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}}
	for i := range 8 {
		n.Ports = append(n.Ports, v1beta1.NetworkPort{Name: fmt.Sprintf("TCP-%d", 8000+i), Protocol: "TCP", Port: new(int32(8000 + i))})
	}
	return n
}

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
