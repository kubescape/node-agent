package queue

import (
	"context"
	"strings"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func TestQueueSizeBudgetRetainsUnsplittableAndDepthLimitedData(t *testing.T) {
	for _, count := range []int{1, 8} {
		name := "unsplittable"
		if count > 1 {
			name = "depth limit"
		}
		t.Run(name, func(t *testing.T) {
			creator := &MockProfileCreator{}
			q, err := NewQueueData(context.Background(), creator, QueueConfig{QueueName: "budget", QueueDir: t.TempDir(), MaxQueueSize: 100, ItemsPerSegment: 10, MaxSplitDepth: 2})
			require.NoError(t, err)
			defer q.Close()
			original := &v1beta1.ContainerProfile{Name: "profile", Annotations: map[string]string{
				helpersv1.PreviousReportTimestampMetadataKey: time.Time{}.String(),
				helpersv1.ReportTimestampMetadataKey:         time.Now().String(),
			}}
			for i := range count {
				original.Spec.Syscalls = append(original.Spec.Syscalls, strings.Repeat(string(rune('a'+i)), 100))
			}
			require.NoError(t, q.EnqueueWithSizeLimit(original, "container", 1))
			// Process deterministically without the queue goroutine. The inherited budget
			// must split again on the second pass, then send despite the remaining overage.
			for range 3 {
				q.processAllItems()
			}
			profiles := creator.CreatedProfiles()
			require.Len(t, profiles, min(count, 4))
			var syscalls []string
			var rows []tsRow
			for _, p := range profiles {
				syscalls = append(syscalls, p.Spec.Syscalls...)
				rows = append(rows, tsRow{PreviousReportTimestamp: p.Annotations[helpersv1.PreviousReportTimestampMetadataKey], ReportTimestamp: p.Annotations[helpersv1.ReportTimestampMetadataKey]})
			}
			require.ElementsMatch(t, original.Spec.Syscalls, syscalls)
			assertChainIsLinear(t, rows, original.Annotations[helpersv1.PreviousReportTimestampMetadataKey], original.Annotations[helpersv1.ReportTimestampMetadataKey])
			require.Zero(t, q.GetQueueSize())
		})
	}
}
