// A disposable experiment collector. It keeps only RuntimeObservation records
// and a fixed attribute allowlist, not general node-agent logs or arguments.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	logs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type capture struct {
	logs.UnimplementedLogsServiceServer
	mu   sync.Mutex
	file *os.File
}

func (c *capture) Export(_ context.Context, request *logs.ExportLogsServiceRequest) (*logs.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	allowed := map[string]bool{"source": true, "kind": true, "identity_status": true, "identity_origin": true, "node": true, "container.id": true, "sandbox_id": true, "runtime_handler": true, "namespace": true, "pod_name": true, "pod_uid": true, "container_name": true, "sender_reported_drops": true}
	wire, err := proto.Marshal(request)
	if err != nil {
		return nil, err
	}
	canaryFound := bytes.Contains(wire, []byte("GVS_INTEGRATION_CANARY_2026"))
	clear(wire)
	if canaryFound {
		if err := json.NewEncoder(c.file).Encode(map[string]any{"body": "CapturePrivacyFailure", "canary_received": true}); err != nil {
			return nil, err
		}
	}
	for _, resource := range request.ResourceLogs {
		for _, scope := range resource.ScopeLogs {
			for _, record := range scope.LogRecords {
				if record.Body.GetStringValue() != "RuntimeObservation" {
					continue
				}
				output := map[string]any{"body": "RuntimeObservation", "observed_time_unix_nano": record.ObservedTimeUnixNano, "wire_canary_found": canaryFound}
				unexpected := 0
				for _, kv := range record.Attributes {
					if !allowed[kv.Key] {
						unexpected++
						continue
					}
					if kv.Key == "sender_reported_drops" {
						output[kv.Key] = kv.Value.GetIntValue()
					} else {
						output[kv.Key] = kv.Value.GetStringValue()
					}
				}
				output["unexpected_attribute_count"] = unexpected
				if err := json.NewEncoder(c.file).Encode(output); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := c.file.Sync(); err != nil {
		return nil, err
	}
	return &logs.ExportLogsServiceResponse{}, nil
}
func main() {
	listen := flag.String("listen", "127.0.0.1:4317", "bind only a trusted local experiment address")
	output := flag.String("output", "observations.jsonl", "new sanitized output file")
	flag.Parse()
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		panic("cannot create experiment output")
	}
	defer file.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		panic("cannot listen for experiment logs")
	}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(1 << 20))
	logs.RegisterLogsServiceServer(server, &capture{file: file})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); server.Stop() }()
	if err := server.Serve(listener); err != nil && ctx.Err() == nil {
		panic("experiment log collector failed")
	}
}
