package utils

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
	"github.com/stretchr/testify/assert"
)

func TestStructEventGetDirection(t *testing.T) {
	tests := []struct {
		name      string
		event     *StructEvent
		expectDir consts.NetworkDirection
	}{
		{
			name:      "HTTP event with explicit direction Inbound",
			event:     &StructEvent{EventType: HTTPEventType, Direction: consts.Inbound},
			expectDir: consts.Inbound,
		},
		{
			name:      "HTTP event with explicit direction Outbound",
			event:     &StructEvent{EventType: HTTPEventType, Direction: consts.Outbound},
			expectDir: consts.Outbound,
		},
		{
			name:      "Network event with no Direction set and OUTGOING packet type maps to Outbound",
			event:     &StructEvent{EventType: NetworkEventType, PktType: "OUTGOING"},
			expectDir: consts.Outbound,
		},
		{
			name:      "Network event with no Direction set and HOST packet type maps to Inbound",
			event:     &StructEvent{EventType: NetworkEventType, PktType: "HOST"},
			expectDir: consts.Inbound,
		},
		{
			name:      "Network event with explicit Inbound direction ignores packet type",
			event:     &StructEvent{EventType: NetworkEventType, Direction: consts.Inbound, PktType: "OUTGOING"},
			expectDir: consts.Inbound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectDir, tt.event.GetDirection())
		})
	}
}

type mockFieldAccessor struct {
	datasource.FieldAccessor
	val uint8
}

func (m *mockFieldAccessor) Uint8(data datasource.Data) (uint8, error) {
	return m.val, nil
}

type mockDataSource struct {
	datasource.DataSource
	fields map[string]datasource.FieldAccessor
}

func (m *mockDataSource) GetField(name string) datasource.FieldAccessor {
	return m.fields[name]
}

func TestDatasourceEventGetDirection(t *testing.T) {
	// Create mock datasource that has a field "egress" returning a mockFieldAccessor
	dsOutgoing := &mockDataSource{
		fields: map[string]datasource.FieldAccessor{
			"egress": &mockFieldAccessor{val: 1},
		},
	}
	dsHost := &mockDataSource{
		fields: map[string]datasource.FieldAccessor{
			"egress": &mockFieldAccessor{val: 0},
		},
	}

	tests := []struct {
		name      string
		event     *DatasourceEvent
		expectDir consts.NetworkDirection
	}{
		{
			name: "Network event with egress=1 maps to Outbound",
			event: &DatasourceEvent{
				EventType:  NetworkEventType,
				Datasource: dsOutgoing,
			},
			expectDir: consts.Outbound,
		},
		{
			name: "Network event with egress=0 maps to Inbound",
			event: &DatasourceEvent{
				EventType:  NetworkEventType,
				Datasource: dsHost,
			},
			expectDir: consts.Inbound,
		},
		{
			name: "Non-network event doesn't map egress to outbound",
			event: &DatasourceEvent{
				EventType:  HTTPEventType,
				Datasource: dsOutgoing,
			},
			expectDir: "",
		},
		{
			name: "HTTP event with explicit direction Inbound",
			event: &DatasourceEvent{
				EventType: HTTPEventType,
				Direction: consts.Inbound,
			},
			expectDir: consts.Inbound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear package-level fieldCaches maps so we don't bleed cache between tests
			fieldCaches.Range(func(key, val interface{}) bool {
				fieldCaches.Delete(key)
				return true
			})
			assert.Equal(t, tt.expectDir, tt.event.GetDirection())
		})
	}
}
