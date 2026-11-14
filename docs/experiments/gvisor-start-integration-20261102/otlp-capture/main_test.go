package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	logs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	logpb "go.opentelemetry.io/proto/otlp/logs/v1"
)

func TestCaptureChecksWireBeforeFiltering(t *testing.T) {
	for _, canary := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "sensitive_extra_attribute"}[canary], func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "capture")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			record := &logpb.LogRecord{Body: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "RuntimeObservation"}}}
			if canary {
				record.Attributes = []*common.KeyValue{{Key: "args", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "GVS_INTEGRATION_CANARY_2026"}}}}
			}
			request := &logs.ExportLogsServiceRequest{ResourceLogs: []*logpb.ResourceLogs{{ScopeLogs: []*logpb.ScopeLogs{{LogRecords: []*logpb.LogRecord{record}}}}}}
			collector := &capture{file: file}
			if _, err := collector.Export(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "GVS_INTEGRATION_CANARY_2026") {
				t.Fatal("sensitive attribute retained")
			}
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			var last map[string]any
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
				t.Fatal(err)
			}
			if last["wire_canary_found"] != canary {
				t.Fatal("wire canary detection defeated by filtering")
			}
			if canary && (len(lines) != 2 || last["unexpected_attribute_count"] != float64(1)) {
				t.Fatal("privacy violation was hidden")
			}
		})
	}
}
