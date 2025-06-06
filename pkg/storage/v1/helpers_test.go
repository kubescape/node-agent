package storage

import (
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsComplete(t *testing.T) {
	tests := []struct {
		name               string
		annotations        map[string]string
		completionStatus   utils.WatchedContainerCompletionStatus
		expectedIsComplete bool
	}{
		{
			name: "complete when status=Completed and completion=Complete",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Completed,
				helpers.CompletionMetadataKey: helpers.Complete,
			},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: true,
		},
		{
			name: "complete when status=Completed, completion=Partial, and newCompletionStatus=Partial",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Completed,
				helpers.CompletionMetadataKey: helpers.Partial,
			},
			completionStatus:   utils.WatchedContainerCompletionStatusPartial,
			expectedIsComplete: true,
		},
		{
			name: "not complete when status=Completed, completion=Partial, but newCompletionStatus=Full",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Completed,
				helpers.CompletionMetadataKey: helpers.Partial,
			},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: false,
		},
		{
			name: "not complete when status=Ready",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Ready,
				helpers.CompletionMetadataKey: helpers.Complete,
			},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: false,
		},
		{
			name: "not complete when status is missing",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: helpers.Complete,
			},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: false,
		},
		{
			name: "not complete when completion is missing",
			annotations: map[string]string{
				helpers.StatusMetadataKey: helpers.Completed,
			},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: false,
		},
		{
			name:               "not complete when annotations are empty",
			annotations:        map[string]string{},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: false,
		},
		{
			name: "not complete when annotations are invalid",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     "InvalidStatus",
				helpers.CompletionMetadataKey: "InvalidCompletion",
			},
			completionStatus:   utils.WatchedContainerCompletionStatusFull,
			expectedIsComplete: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isComplete := IsComplete(tc.annotations, tc.completionStatus)
			assert.Equal(t, tc.expectedIsComplete, isComplete, "IsComplete should return the expected result")
		})
	}
}

func TestIsSeenFromStart(t *testing.T) {
	tests := []struct {
		name                    string
		annotations             map[string]string
		watchedContainer        *utils.WatchedContainerData
		expectedIsSeenFromStart bool
	}{
		{
			name: "seen from start when completion=Complete and container status=Partial",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: helpers.Complete,
			},
			watchedContainer:        &utils.WatchedContainerData{},
			expectedIsSeenFromStart: true,
		},
		{
			name: "not seen from start when completion=Partial",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: helpers.Partial,
			},
			watchedContainer:        &utils.WatchedContainerData{},
			expectedIsSeenFromStart: false,
		},
		{
			name: "not seen from start when completion is missing",
			annotations: map[string]string{
				helpers.StatusMetadataKey: helpers.Completed,
			},
			watchedContainer:        &utils.WatchedContainerData{},
			expectedIsSeenFromStart: false,
		},
		{
			name:                    "not seen from start when annotations are empty",
			annotations:             map[string]string{},
			watchedContainer:        &utils.WatchedContainerData{},
			expectedIsSeenFromStart: false,
		},
		{
			name: "not seen from start when completion is invalid",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: "InvalidCompletion",
			},
			watchedContainer:        &utils.WatchedContainerData{},
			expectedIsSeenFromStart: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set container's completion status to Partial
			tc.watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)

			isSeenFromStart := IsSeenFromStart(tc.annotations, tc.watchedContainer)
			assert.Equal(t, tc.expectedIsSeenFromStart, isSeenFromStart, "IsSeenFromStart should return the expected result")
		})
	}
}