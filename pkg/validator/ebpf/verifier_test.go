package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		major   uint
		minor   uint
		patch   uint
		wantErr bool
	}{
		{
			name:  "4.15.0-112-generic",
			major: 4,
			minor: 15,
			patch: 0,
		},
		{
			name:  "6.11+parrot-amd64",
			major: 6,
			minor: 11,
			patch: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, err := ParseKernelVersion(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKernelVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.major, got)
			assert.Equal(t, tt.minor, got1)
			assert.Equal(t, tt.patch, got2)
		})
	}
}
