package storage

import (
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsComplete(t *testing.T) {
	tests := []struct {
		name             string
		annotations      map[string]string
		containerData    *utils.WatchedContainerData
		expectedComplete bool
	}{
		{
			name: "complete and completed",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Complete,
				helpers.CompletionMetadataKey: helpers.Completed,
			},
			containerData:    &utils.WatchedContainerData{},
			expectedComplete: true,
		},
		{
			name: "complete and partial with container partial",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Complete,
				helpers.CompletionMetadataKey: helpers.Partial,
			},
			containerData:    &utils.WatchedContainerData{},
			expectedComplete: false,
		},
		{
			name: "complete and partial with container partial status",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     helpers.Complete,
				helpers.CompletionMetadataKey: helpers.Partial,
			},
			containerData: func() *utils.WatchedContainerData {
				c := &utils.WatchedContainerData{}
				c.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
				return c
			}(),
			expectedComplete: true,
		},
		{
			name:             "missing annotations",
			annotations:      map[string]string{},
			containerData:    &utils.WatchedContainerData{},
			expectedComplete: false,
		},
		{
			name: "missing status annotation",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: helpers.Completed,
			},
			containerData:    &utils.WatchedContainerData{},
			expectedComplete: false,
		},
		{
			name: "incorrect status values",
			annotations: map[string]string{
				helpers.StatusMetadataKey:     "incorrect",
				helpers.CompletionMetadataKey: helpers.Completed,
			},
			containerData:    &utils.WatchedContainerData{},
			expectedComplete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsComplete(tt.annotations, tt.containerData)
			assert.Equal(t, tt.expectedComplete, result)
		})
	}
}

func TestIsSeenFromStart(t *testing.T) {
	tests := []struct {
		name                  string
		annotations           map[string]string
		containerData         *utils.WatchedContainerData
		expectedSeenFromStart bool
	}{
		{
			name: "seen from start - complete and container partial",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: helpers.Complete,
			},
			containerData: func() *utils.WatchedContainerData {
				c := &utils.WatchedContainerData{}
				c.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
				return c
			}(),
			expectedSeenFromStart: true,
		},
		{
			name:        "not seen from start - missing completion metadata",
			annotations: map[string]string{},
			containerData: func() *utils.WatchedContainerData {
				c := &utils.WatchedContainerData{}
				c.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
				return c
			}(),
			expectedSeenFromStart: false,
		},
		{
			name: "not seen from start - incorrect completion value",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: "incorrect",
			},
			containerData: func() *utils.WatchedContainerData {
				c := &utils.WatchedContainerData{}
				c.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
				return c
			}(),
			expectedSeenFromStart: false,
		},
		{
			name: "not seen from start - container not partial",
			annotations: map[string]string{
				helpers.CompletionMetadataKey: helpers.Complete,
			},
			containerData: func() *utils.WatchedContainerData {
				c := &utils.WatchedContainerData{}
				c.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
				return c
			}(),
			expectedSeenFromStart: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSeenFromStart(tt.annotations, tt.containerData)
			assert.Equal(t, tt.expectedSeenFromStart, result)
		})
	}
}
