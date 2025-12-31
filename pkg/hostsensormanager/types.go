package hostsensormanager

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// API group and version for host data CRDs
	HostDataGroup   = "hostdata.kubescape.cloud"
	HostDataVersion = "v1beta1"
)

// HostSensorManager manages the lifecycle of host sensors
type HostSensorManager interface {
	// Start begins the sensing loop
	Start(ctx context.Context) error
	// Stop gracefully stops the manager
	Stop() error
}

// Sensor represents a single host sensor that can collect data
type Sensor interface {
	// Sense collects the data from the host
	Sense() (interface{}, error)
	// GetKind returns the CRD kind for this sensor
	GetKind() string
}

// OsReleaseFile represents the CRD structure for OS release data
type OsReleaseFile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OsReleaseFileSpec   `json:"spec,omitempty"`
	Status OsReleaseFileStatus `json:"status,omitempty"`
}

// OsReleaseFileSpec contains the actual OS release file content
type OsReleaseFileSpec struct {
	Content  string `json:"content"`
	NodeName string `json:"nodeName"`
}

// OsReleaseFileStatus contains status information about the sensing
type OsReleaseFileStatus struct {
	LastSensed metav1.Time `json:"lastSensed,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// OsReleaseFileList contains a list of OsReleaseFile
type OsReleaseFileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OsReleaseFile `json:"items"`
}

// Config holds the configuration for the host sensor manager
type Config struct {
	Enabled  bool
	Interval time.Duration
	NodeName string
}
