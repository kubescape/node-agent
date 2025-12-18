# NodeAgent

<p align="center">
  <img src="https://raw.githubusercontent.com/cncf/artwork/master/projects/kubescape/icon/color/kubescape-icon-color.svg" alt="Kubescape Logo" width="150"/>
</p>

<p align="center">
  <a href="https://www.cncf.io/projects/kubescape/"><img src="https://img.shields.io/badge/CNCF-Incubating-blue?logo=cncf" alt="CNCF Incubating"></a>
  <a href="https://github.com/kubescape/node-agent/releases"><img src="https://img.shields.io/github/v/release/kubescape/node-agent" alt="Version"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/kubescape/node-agent" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/kubescape/node-agent"><img src="https://api.securityscorecards.dev/projects/github.com/kubescape/node-agent/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer?ref=badge_shield&issueType=license"><img src="https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fsniffer.svg?type=shield&issueType=license" alt="FOSSA Status"></a>
  <a href="https://github.com/kubescape/node-agent/stargazers"><img src="https://img.shields.io/github/stars/kubescape/node-agent?style=social" alt="Stars"></a>
</p>

<p align="center">
  <b>Real-time Kubernetes runtime security powered by eBPF</b>
</p>

---

**NodeAgent** is a Kubernetes runtime security agent that uses eBPF (extended Berkeley Packet Filter) to detect and prevent threats in real-time. It's a core component of the [Kubescape](https://kubescape.io) security platform, a CNCF incubating project.

NodeAgent monitors container behavior at the kernel level, learns normal application patterns, and alerts on anomalies and known attack techniques—all with minimal performance overhead.

## 🛡️ Why Use NodeAgent?

- **Zero-Config Threat Detection**: Automatically detects command injection, privilege escalation, crypto miners, and more
- **Behavioral Learning**: Learns your application's normal behavior and alerts on anomalies
- **eBPF-Powered**: Kernel-level visibility with minimal performance impact (~1-2% CPU overhead)
- **Image-Based Gadgets**: Modern, portable eBPF programs using [Inspektor Gadget](https://www.inspektor-gadget.io/) image format
- **Cloud-Native**: Built for Kubernetes, integrates with existing security workflows
- **Open Source**: Apache 2.0 licensed, CNCF incubating project

## ✨ Features

| Category | Features |
|----------|----------|
| **Runtime Detection** | Unexpected process execution, shell spawning, privilege escalation, container escape attempts |
| **Malware Scanning** | ClamAV-powered scanning for trojans, cryptominers, webshells, ransomware |
| **Network Security** | DNS monitoring, network connection tracking, data exfiltration detection |
| **Application Profiling** | Automatic baseline learning, seccomp profile generation |
| **File Integrity** | Real-time file change monitoring (FIM) with fanotify backend |
| **SBOM Generation** | Automatic Software Bill of Materials creation |
| **Crypto Mining Detection** | RandomX instruction detection for cryptojacking |
| **Attack Detection** | Fileless malware, eBPF program loading, kernel module insertion |

## 📖 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Image-Based Gadgets](#-image-based-gadgets)
- [Detection Rules](#-detection-rules)
- [Demos & Examples](#-demos--examples)
- [Troubleshooting](#-troubleshooting)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

Get NodeAgent running in your cluster in under 5 minutes:

```bash
# Add the Kubescape Helm repository
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

# Install with runtime detection enabled
helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName=$(kubectl config current-context) \
  --set capabilities.runtimeDetection=enable \
  --set alertCRD.installDefault=true

# Wait for node-agent pods to be ready
kubectl wait --for=condition=Ready pods -l app=node-agent -n kubescape --timeout=300s

# View alerts (after learning period completes)
kubectl logs -n kubescape -l app=node-agent -f
```

**Test it out:**
```bash
# After the learning period (~2 minutes by default), run:
kubectl exec -it <any-pod> -- sh -c "cat /etc/passwd"

# You should see an alert in the node-agent logs!
```

## 📦 Installation

### Kubernetes (Recommended)

Deploy NodeAgent as part of the Kubescape operator:

```bash
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName=$(kubectl config current-context) \
  --set capabilities.runtimeDetection=enable \
  --set capabilities.malwareDetection=enable \
  --set alertCRD.installDefault=true \
  --set alertCRD.scopeClustered=true
```

**With AlertManager integration:**
```bash
helm upgrade --install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  --set clusterName=$(kubectl config current-context) \
  --set capabilities.runtimeDetection=enable \
  --set nodeAgent.config.alertManagerExporterUrls=alertmanager-operated.monitoring.svc.cluster.local:9093
```

For full configuration options, see the [Kubescape documentation](https://kubescape.io/docs/).

### Standalone (Development/Testing)

Build and run NodeAgent directly on a Linux host:

```bash
# Clone the repository
git clone https://github.com/kubescape/node-agent.git
cd node-agent

# Build the binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o node-agent ./cmd/main.go

# Set required environment variables
export NODE_NAME=$(hostname)
export KUBECONFIG=~/.kube/config

# Run with root privileges (required for eBPF)
sudo ./node-agent
```

### Docker

```bash
# Build the image
docker buildx build -t node-agent -f build/Dockerfile --load .

# Run (requires privileged mode for eBPF)
docker run --privileged --pid=host --network=host \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  -e NODE_NAME=$(hostname) \
  node-agent
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Node                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         NodeAgent Pod                                │   │
│  │                                                                      │   │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │   │
│  │  │  Tracer Manager  │  │  Rule Manager    │  │  Profile Manager │  │   │
│  │  │                  │  │                  │  │                  │  │   │
│  │  │ • Exec Tracer    │  │ • CEL Evaluator  │  │ • App Profiles   │  │   │
│  │  │ • Open Tracer    │  │ • Rule Bindings  │  │ • Network Neigh. │  │   │
│  │  │ • Network Tracer │  │ • Cooldown Mgmt  │  │ • Seccomp Gen.   │  │   │
│  │  │ • DNS Tracer     │  │                  │  │                  │  │   │
│  │  │ • + 15 more...   │  │                  │  │                  │  │   │
│  │  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │   │
│  │           │                     │                     │            │   │
│  │           └─────────────────────┼─────────────────────┘            │   │
│  │                                 │                                  │   │
│  │                    ┌────────────▼────────────┐                     │   │
│  │                    │   Ordered Event Queue   │                     │   │
│  │                    │   (Process Tree Aware)  │                     │   │
│  │                    └────────────┬────────────┘                     │   │
│  │                                 │                                  │   │
│  │           ┌─────────────────────┼─────────────────────┐            │   │
│  │           │                     │                     │            │   │
│  │  ┌────────▼─────────┐  ┌────────▼─────────┐  ┌────────▼─────────┐  │   │
│  │  │  HTTP Exporter   │  │ AlertMgr Export  │  │  Stdout Export   │  │   │
│  │  │  (Alert Bulking) │  │                  │  │                  │  │   │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘  │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    │ eBPF                                   │
│                                    ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                           Linux Kernel                                │  │
│  │                                                                       │  │
│  │   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │  │
│  │   │  exec   │ │  open   │ │ network │ │   dns   │ │  kmod   │ ...   │  │
│  │   │ probes  │ │ probes  │ │ probes  │ │ probes  │ │ probes  │       │  │
│  │   └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘       │  │
│  │                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐                        │
│  │Container│  │Container│  │Container│  │Container│  ...                   │
│  │   A     │  │   B     │  │   C     │  │   D     │                        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| **Tracer Manager** | Manages eBPF-based tracers for different syscalls and events |
| **Rule Manager** | Evaluates security rules using CEL expressions |
| **Profile Manager** | Learns and maintains application behavior profiles |
| **Ordered Event Queue** | Ensures events are processed in correct order with process tree awareness |
| **Alert Bulk Manager** | Batches alerts for efficient transmission |
| **Malware Manager** | Coordinates ClamAV scanning for malware detection |
| **SBOM Manager** | Generates Software Bill of Materials using Syft |

## ⚙️ Configuration

NodeAgent is configured through a JSON configuration file and environment variables.

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `NODE_NAME` | Kubernetes node name | Yes (in K8s) | - |
| `POD_NAME` | Pod name | Yes (in K8s) | - |
| `NAMESPACE_NAME` | Namespace | Yes (in K8s) | - |
| `KUBECONFIG` | Path to kubeconfig | Standalone only | - |
| `CONFIG_DIR` | Configuration directory | No | `/etc/config` |
| `SKIP_KERNEL_VERSION_CHECK` | Skip kernel validation | No | - |
| `ENABLE_PROFILER` | Enable pprof on port 6060 | No | - |
| `OTEL_COLLECTOR_SVC` | OpenTelemetry collector address | No | - |
| `PYROSCOPE_SERVER_SVC` | Pyroscope server address | No | - |

### Configuration File

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete configuration reference.

**Example minimal config:**
```json
{
  "applicationProfileServiceEnabled": true,
  "runtimeDetectionEnabled": true,
  "malwareDetectionEnabled": true,
  "networkServiceEnabled": true,
  "prometheusExporterEnabled": true
}
```

### Feature Toggles

| Feature | Config Key | Default | Description |
|---------|------------|---------|-------------|
| Application Profiling | `applicationProfileServiceEnabled` | `false` | Learn container behavior |
| Runtime Detection | `runtimeDetectionEnabled` | `false` | Enable threat detection rules |
| Malware Detection | `malwareDetectionEnabled` | `false` | ClamAV-based scanning |
| Network Tracing | `networkServiceEnabled` | `false` | Track network connections |
| SBOM Generation | `sbomGenerationEnabled` | `false` | Generate SBOMs |
| File Integrity | `fimEnabled` | `false` | Monitor file changes |
| Seccomp Profiles | `seccompServiceEnabled` | `false` | Generate seccomp profiles |
| HTTP Detection | `httpDetectionEnabled` | `false` | Parse HTTP traffic |
| Network Streaming | `networkStreamingEnabled` | `false` | Stream network events |

## 🔌 Image-Based Gadgets

NodeAgent uses [Inspektor Gadget's](https://www.inspektor-gadget.io/) image-based gadget format for portable, versioned eBPF programs.

### Built-in Gadgets

| Gadget | Event Type | Description |
|--------|------------|-------------|
| `exec` | `execve` | Process execution events |
| `open` | `open` | File open operations |
| `network` | `network` | Network connections |
| `dns` | `dns` | DNS queries and responses |
| `capabilities` | `capabilities` | Capability checks |
| `seccomp` | `syscall` | System call monitoring |
| `exit` | `exit` | Process termination |
| `fork` | `fork` | Process creation |
| `symlink` | `symlink` | Symbolic link operations |
| `hardlink` | `hardlink` | Hard link operations |
| `ptrace` | `ptrace` | Ptrace operations |
| `kmod` | `kmod` | Kernel module loading |
| `ssh` | `ssh` | SSH connection events |
| `http` | `http` | HTTP request/response |
| `randomx` | `randomx` | RandomX crypto instructions |
| `iouring` | `iouring` | io_uring operations |
| `unshare` | `unshare` | Namespace operations |
| `bpf` | `bpf` | eBPF syscall monitoring |

### Building Gadgets

```bash
# Build all Kubescape gadgets
make gadgets

# Build a specific gadget
make -C ./pkg/ebpf/gadgets/exec build IMAGE=exec TAG=latest
```

### Third-Party Gadgets

NodeAgent supports registering custom third-party tracers. See the `ThirdPartyTracers` interface in `pkg/containerwatcher/container_watcher_interface.go`.

## 🔍 Detection Rules

NodeAgent uses CEL (Common Expression Language) for flexible rule definition. Rules are defined as Kubernetes Custom Resources.

### Example Rule Binding

```yaml
apiVersion: kubescape.io/v1
kind: RuntimeAlertRuleBinding
metadata:
  name: default-rules
spec:
  ruleset:
    - ruleName: "Unexpected Process Launched"
      ruleID: "R0001"
      severity: high
    - ruleName: "Crypto Mining Detected"
      ruleID: "R1001"
      severity: critical
  namespaceSelector:
    matchLabels:
      environment: production
```

### Built-in Rule Categories

- **Process Rules**: Unexpected executables, shell spawning, script execution
- **File Rules**: Sensitive file access, file integrity violations
- **Network Rules**: Unexpected connections, DNS tunneling, data exfiltration
- **Privilege Rules**: Capability usage, privilege escalation attempts
- **Crypto Rules**: Mining activity detection via RandomX
- **Container Rules**: Escape attempts, namespace manipulation

For the full list of rules, see the [Kubescape documentation](https://kubescape.io/docs/).

## 🎮 Demos & Examples

We provide comprehensive demos showcasing NodeAgent's capabilities:

### Available Demos

| Demo | Description | Location |
|------|-------------|----------|
| **Web App Attack** | Command injection detection | `demo/general_attack/` |
| **Fileless Malware** | Memory-only malware detection | `demo/fileless_exec/` |
| **Malicious Image** | Image with embedded malware | `demo/malwares_image/` |
| **Crypto Miner** | XMRig mining detection | `demo/miner/` |

### Running the Demo

```bash
# Follow the complete walkthrough
cat demo/README.md

# Or run individual demos:

# 1. Deploy vulnerable web app
./demo/general_attack/webapp/setup.sh

# 2. Attack it and watch NodeAgent detect:
#    - Command injection
#    - Service account token access
#    - Kubernetes API access

# 3. Deploy fileless malware
kubectl apply -f demo/fileless_exec/kubernetes-manifest.yaml

# 4. Deploy image with malware
kubectl run malware-cryptominer --image=quay.io/petr_ruzicka/malware-cryptominer-container:2.0.2

# 5. Check alerts
kubectl logs -n kubescape -l app=node-agent -f
```

See the full [Demo Guide](demo/README.md) for detailed instructions with screenshots.

## 🔧 Troubleshooting

### Common Issues

#### NodeAgent pod not starting

```bash
# Check pod status
kubectl get pods -n kubescape -l app=node-agent

# Check logs
kubectl logs -n kubescape -l app=node-agent --previous

# Common causes:
# - Kernel version too old (need 5.4+)
# - Missing BTF support
# - Insufficient privileges
```

#### No alerts being generated

```bash
# 1. Check if learning period is complete (default: 2 minutes)
kubectl logs -n kubescape -l app=node-agent | grep "learning"

# 2. Verify rule bindings are applied
kubectl get runtimealertruleinding -A

# 3. Check if the namespace is excluded
kubectl get configmap -n kubescape kubescape-config -o yaml | grep excludeNamespaces
```

#### High CPU usage

```bash
# Check current configuration
kubectl get configmap -n kubescape node-agent-config -o yaml

# Tune these settings:
# - workerPoolSize (default: 3000)
# - eventBatchSize (default: 15000)
# - Disable unused features
```

#### eBPF verification errors

```bash
# Check kernel version
uname -r  # Should be 5.4+

# Check BTF support
ls -la /sys/kernel/btf/vmlinux

# Check if running in a supported environment
# (Some minimal containers lack required mounts)
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `100` | runc not found |
| `101` | Incompatible kernel |
| `102` | macOS (unsupported) |

### Getting Help

1. Check the [Kubescape documentation](https://kubescape.io/docs/)
2. Search [GitHub Issues](https://github.com/kubescape/node-agent/issues)
3. Join the [CNCF Slack](https://cloud-native.slack.com/archives/C04EY3ZF9GE) (#kubescape channel)
4. Email: support@armosec.io

## 🛠️ Development

### Prerequisites

- Go 1.25+
- Linux with kernel 5.4+ (for eBPF)
- Docker (for building images)
- kubectl & helm (for testing)
- Root/sudo access (for running eBPF programs)

### Building

```bash
# Clone the repository
git clone https://github.com/kubescape/node-agent.git
cd node-agent

# Build binary
make binary

# Build Docker image
make docker-build

# Build with gadgets
make docker-build  # Includes gadget building
```

### Running Tests

```bash
# Unit tests
go test ./...

# With race detection
go test -race ./...

# Integration tests (requires cluster)
go test ./tests/...
```

### Debugging

**VS Code launch configuration:**
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch NodeAgent",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/cmd/main.go",
            "env": {
                "NODE_NAME": "<node-name>",
                "KUBECONFIG": "<path-to-kubeconfig>"
            },
            "console": "integratedTerminal",
            "asRoot": true
        }
    ]
}
```

**Enable profiling:**
```bash
export ENABLE_PROFILER=true
sudo ./node-agent
# Then access http://localhost:6060/debug/pprof/
```

### Project Structure

```
node-agent/
├── cmd/                    # Main entry point
├── pkg/
│   ├── config/            # Configuration handling
│   ├── containerwatcher/  # Container event monitoring
│   │   └── v2/tracers/    # eBPF tracer implementations
│   ├── ebpf/gadgets/      # Image-based eBPF gadgets
│   ├── exporters/         # Alert exporters (HTTP, AlertManager, etc.)
│   ├── malwaremanager/    # Malware detection with ClamAV
│   ├── rulemanager/       # CEL-based rule evaluation
│   ├── sbommanager/       # SBOM generation
│   └── ...
├── demo/                   # Demo applications and guides
├── docs/                   # Additional documentation
├── build/                  # Dockerfiles
└── tests/                  # Integration tests
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md).

### Quick Links

- [Code of Conduct](https://github.com/kubescape/project-governance/blob/main/CODE_OF_CONDUCT.md)
- [Governance](https://github.com/kubescape/project-governance/blob/main/GOVERNANCE.md)
- [Security Policy](https://github.com/kubescape/project-governance/blob/main/SECURITY.md)
- [Maintainers](https://github.com/kubescape/project-governance/blob/main/MAINTAINERS.md)

## 📄 License

NodeAgent is licensed under the [Apache License 2.0](LICENSE).

## 📚 Additional Resources

- [Kubescape Documentation](https://kubescape.io/docs/)
- [Alert Bulking Architecture](docs/ALERT_BULKING.md)
- [Process Tree Optimization](docs/PROCESS_TREE_CHAIN_OPTIMIZATION.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [CNCF Kubescape Project](https://www.cncf.io/projects/kubescape/)

## 📝 Changelog

See the [Releases](https://github.com/kubescape/node-agent/releases) page for version history and changelogs.

---

<p align="center">
  Made with ❤️ by the <a href="https://github.com/kubescape">Kubescape</a> community
</p>