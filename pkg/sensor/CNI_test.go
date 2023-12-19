package sensor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getCNINames(t *testing.T) {
	uid_tests := []struct {
		name     string
		expected []string
	}{
		{
			name:     "no_cni",
			expected: []string(nil),
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cniList := getCNINames(ctx)
			if !assert.Equal(t, cniList, tt.expected) {
				t.Logf("%s has different value", tt.name)
			}
		})
	}
}
