package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRawProfileDataRequired(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil is valid",
			raw:     nil,
			wantErr: false,
		},
		{
			name: "valid all and patterns",
			raw: map[string]any{
				"opens": "all",
				"execs": []any{
					map[string]any{"exact": "/bin/sh"},
					map[string]any{"prefix": "/usr/"},
				},
			},
			wantErr: false,
		},
		{
			name: "unknown surface key",
			raw: map[string]any{
				"open": "all",
			},
			wantErr: true,
			errMsg:  `unknown field "open"`,
		},
		{
			name: "unknown pattern key",
			raw: map[string]any{
				"opens": []any{
					map[string]any{"exct": "/bin/sh"},
				},
			},
			wantErr: true,
			errMsg:  `unknown field "exct"`,
		},
		{
			name: "invalid string value",
			raw: map[string]any{
				"opens": "none",
			},
			wantErr: true,
			errMsg:  `string value must be "all"`,
		},
		{
			name: "empty pattern list",
			raw: map[string]any{
				"opens": []any{},
			},
			wantErr: true,
			errMsg:  "pattern list must not be empty",
		},
		{
			name: "empty pattern object",
			raw: map[string]any{
				"opens": []any{map[string]any{}},
			},
			wantErr: true,
			errMsg:  "empty pattern object",
		},
		{
			name:    "non-map input",
			raw:     "all",
			wantErr: true,
			errMsg:  "must be a map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRawProfileDataRequired(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
