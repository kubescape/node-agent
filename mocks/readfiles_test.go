package mocks

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnstructuredToPod(t *testing.T) {

	tests := []struct {
		name TestName
		kind TestKinds
	}{
		{
			name: TestNginx,
			kind: TestKindPod,
		},
		{
			name: TestNginx,
			kind: TestKindRS,
		},
		{
			name: TestNginx,
			kind: TestKindDeploy,
		},
		{
			name: TestNginx,
			kind: TestKindAA,
		},
		{
			name: TestNginx,
			kind: TestKindAP,
		},
		{
			name: TestNginx,
			kind: TestKindNN,
		},
		{
			name: TestCollection,
			kind: TestKindPod,
		},
		{
			name: TestCollection,
			kind: TestKindRS,
		},
		{
			name: TestCollection,
			kind: TestKindDeploy,
		},
		{
			name: TestCollection,
			kind: TestKindAA,
		},
		{
			name: TestCollection,
			kind: TestKindAP,
		},
		{
			name: TestCollection,
			kind: TestKindNN,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.name, tt.kind), func(t *testing.T) {
			b := GetBytes(tt.kind, tt.name)
			assert.NotEqual(t, 0, len(b))

			u := GetUnstructured(tt.kind, tt.name)
			assert.NotNil(t, u)

			r := GetRuntime(tt.kind, tt.name)
			assert.NotNil(t, r)

		})
	}
}
