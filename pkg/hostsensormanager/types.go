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
	// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
	GetPluralKind() string
}

// Status contains status information about the sensing (common for all host data CRDs)
type Status struct {
	LastSensed metav1.Time `json:"lastSensed,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// FileInfo holds information about a file
type FileInfo struct {
	Ownership   *FileOwnership `json:"ownership"`
	Path        string         `json:"path"`
	Content     []byte         `json:"content,omitempty"`
	Permissions int            `json:"permissions"`
}

// FileOwnership holds the ownership of a file
type FileOwnership struct {
	Err       string `json:"err,omitempty"`
	UID       int64  `json:"uid"`
	GID       int64  `json:"gid"`
	Username  string `json:"username"`
	Groupname string `json:"groupname"`
}

// KernelVariable represents a single kernel variable
type KernelVariable struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// Connection represents a network connection (minimal version of procspy.Connection)
type Connection struct {
	Transport     string `json:"transport"`
	LocalAddress  string `json:"localAddress"`
	LocalPort     uint16 `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    uint16 `json:"remotePort"`
}

// --- OsReleaseFile ---

// OsReleaseFile represents the CRD structure for OS release data
type OsReleaseFile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OsReleaseFileSpec `json:"spec,omitempty"`
	Status Status            `json:"status,omitempty"`
}

// OsReleaseFileSpec contains the actual OS release file content
type OsReleaseFileSpec struct {
	Content  string `json:"content"`
	NodeName string `json:"nodeName"`
}

// --- KernelVersion ---

// KernelVersion represents the CRD structure for kernel version data
type KernelVersion struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KernelVersionSpec `json:"spec,omitempty"`
	Status Status            `json:"status,omitempty"`
}

type KernelVersionSpec struct {
	Content  string `json:"content"`
	NodeName string `json:"nodeName"`
}

// --- LinuxSecurityHardening ---

// LinuxSecurityHardening represents the CRD structure for security hardening data
type LinuxSecurityHardening struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LinuxSecurityHardeningSpec `json:"spec,omitempty"`
	Status Status                     `json:"status,omitempty"`
}

type LinuxSecurityHardeningSpec struct {
	AppArmor string `json:"appArmor"`
	SeLinux  string `json:"seLinux"`
	NodeName string `json:"nodeName"`
}

// --- OpenPorts ---

// OpenPorts represents the CRD structure for open ports data
type OpenPorts struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenPortsSpec `json:"spec,omitempty"`
	Status Status        `json:"status,omitempty"`
}

type OpenPortsSpec struct {
	TcpPorts  []Connection `json:"tcpPorts"`
	UdpPorts  []Connection `json:"udpPorts"`
	ICMPPorts []Connection `json:"icmpPorts"`
	NodeName  string       `json:"nodeName"`
}

// --- LinuxKernelVariables ---

// LinuxKernelVariables represents the CRD structure for kernel variables data
type LinuxKernelVariables struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LinuxKernelVariablesSpec `json:"spec,omitempty"`
	Status Status                   `json:"status,omitempty"`
}

type LinuxKernelVariablesSpec struct {
	KernelVariables []KernelVariable `json:"kernelVariables"`
	NodeName        string           `json:"nodeName"`
}

// --- KubeletInfo ---

// KubeletInfo represents the CRD structure for kubelet info data
type KubeletInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeletInfoSpec `json:"spec,omitempty"`
	Status Status          `json:"status,omitempty"`
}

type KubeletInfoSpec struct {
	ServiceFiles   []FileInfo `json:"serviceFiles,omitempty"`
	ConfigFile     *FileInfo  `json:"configFile,omitempty"`
	KubeConfigFile *FileInfo  `json:"kubeConfigFile,omitempty"`
	ClientCAFile   *FileInfo  `json:"clientCAFile,omitempty"`
	CmdLine        string     `json:"cmdLine"`
	NodeName       string     `json:"nodeName"`
}

// --- KubeProxyInfo ---

// KubeProxyInfo represents the CRD structure for kube-proxy info data
type KubeProxyInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeProxyInfoSpec `json:"spec,omitempty"`
	Status Status            `json:"status,omitempty"`
}

type KubeProxyInfoSpec struct {
	KubeConfigFile *FileInfo `json:"kubeConfigFile,omitempty"`
	CmdLine        string    `json:"cmdLine"`
	NodeName       string    `json:"nodeName"`
}

// --- ControlPlaneInfo ---

// ControlPlaneInfo represents the CRD structure for control plane info data
type ControlPlaneInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ControlPlaneInfoSpec `json:"spec,omitempty"`
	Status Status               `json:"status,omitempty"`
}

type ControlPlaneInfoSpec struct {
	APIServerInfo         *ApiServerInfo `json:"APIServerInfo,omitempty"`
	ControllerManagerInfo *ProcessInfo   `json:"controllerManagerInfo,omitempty"`
	SchedulerInfo         *ProcessInfo   `json:"schedulerInfo,omitempty"`
	EtcdConfigFile        *FileInfo      `json:"etcdConfigFile,omitempty"`
	EtcdDataDir           *FileInfo      `json:"etcdDataDir,omitempty"`
	AdminConfigFile       *FileInfo      `json:"adminConfigFile,omitempty"`
	PKIDir                *FileInfo      `json:"PKIDir,omitempty"`
	PKIFiles              []*FileInfo    `json:"PKIFiles,omitempty"`
	NodeName              string         `json:"nodeName"`
}

type ProcessInfo struct {
	SpecsFile      *FileInfo `json:"specsFile,omitempty"`
	ConfigFile     *FileInfo `json:"configFile,omitempty"`
	KubeConfigFile *FileInfo `json:"kubeConfigFile,omitempty"`
	ClientCAFile   *FileInfo `json:"clientCAFile,omitempty"`
	CmdLine        string    `json:"cmdLine"`
}

type ApiServerInfo struct {
	EncryptionProviderConfigFile *FileInfo `json:"encryptionProviderConfigFile,omitempty"`
	AuditPolicyFile              *FileInfo `json:"auditPolicyFile,omitempty"`
	ProcessInfo                  `json:",inline"`
}

// --- CloudProviderInfo ---

// CloudProviderInfo represents the CRD structure for cloud provider info data
type CloudProviderInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudProviderInfoSpec `json:"spec,omitempty"`
	Status Status                `json:"status,omitempty"`
}

type CloudProviderInfoSpec struct {
	ProviderMetaDataAPIAccess bool   `json:"providerMetaDataAPIAccess"`
	NodeName                  string `json:"nodeName"`
}

// --- CNIInfo ---

// CNIInfo represents the CRD structure for CNI info data
type CNIInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CNIInfoSpec `json:"spec,omitempty"`
	Status Status      `json:"status,omitempty"`
}

type CNIInfoSpec struct {
	CNIConfigFiles []*FileInfo `json:"CNIConfigFiles,omitempty"`
	CNINames       []string    `json:"CNINames,omitempty"`
	NodeName       string      `json:"nodeName"`
}

// Config holds the configuration for the host sensor manager
type Config struct {
	Enabled  bool
	Interval time.Duration
	NodeName string
}
