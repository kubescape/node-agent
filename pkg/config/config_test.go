package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadClusterData(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    ClusterData
		wantErr bool
	}{
		{
			name: "TestLoadClusterData",
			path: "../../configuration",
			want: ClusterData{
				AccountID:   "ed1e102b-13eb-4d25-b078-e10386305b26",
				ClusterName: "gke_armo-test-clusters_us-central1-c_matthias",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadClusterData(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadClusterData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadConfig(t *testing.T) {
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
				EnableRelevancy:  true,
				MaxSniffingTime:  6 * time.Hour,
				UpdateDataPeriod: 1 * time.Minute,
			},
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
