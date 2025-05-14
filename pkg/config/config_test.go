package config

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	b := false
	tests := []struct {
		name    string
		path    string
		want    Config
		wantErr bool
	}{
		{
			name: "TestLoadConfig",
			path: "../../configuration",
			want: Config{
				EnableFullPathTracing:    true,
				EnableApplicationProfile: true,
				EnableMalwareDetection:   true,
				EnableNetworkTracing:     true,
				EnableNodeProfile:        true,
				EnableHttpDetection:      true,
				EnableHostMalwareSensor:  false,
				EnableHostNetworkSensor:  false,
				EnableNetworkStreaming:   false,
				EnableEmbeddedSboms:      false,
				KubernetesMode:           true,
				NetworkStreamingInterval: 2 * time.Minute,
				InitialDelay:             2 * time.Minute,
				MaxSniffingTime:          6 * time.Hour,
				UpdateDataPeriod:         1 * time.Minute,
				NodeProfileInterval:      1 * time.Minute,
				MaxDelaySeconds:          30,
				MaxJitterPercentage:      5,
				MaxImageSize:             5368709120,
				MaxSBOMSize:              20971520,
				EnablePrometheusExporter: true,
				EnableRuntimeDetection:   true,
				EnableSeccomp:            true,
				Exporters: exporters.ExportersConfig{
					SyslogExporter: "http://syslog.kubescape.svc.cluster.local:514",
					StdoutExporter: &b,
					AlertManagerExporterUrls: []string{
						"http://alertmanager.kubescape.svc.cluster.local:9093",
						"http://alertmanager.kubescape.svc.cluster.local:9095",
					},
					CsvRuleExporterPath:    "/rules",
					CsvMalwareExporterPath: "/malware",
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						URL: "http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io",
					},
				},
				WorkerPoolSize: 10,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadConfig(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
