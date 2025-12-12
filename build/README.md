# Building NodeAgent

This directory contains the Docker build configuration for NodeAgent.

## Quick Start

```bash
# Build the Docker image
docker buildx build -t node-agent -f build/Dockerfile --load .
```

## Build Options

### Standard Build

Build for your local architecture:

```bash
docker buildx build -t node-agent:latest -f build/Dockerfile --load .
```

### Multi-Architecture Build

Build for multiple platforms (requires Docker buildx):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t node-agent:latest \
  -f build/Dockerfile \
  --push .
```

### Debug Build

Build with debug symbols and tools:

```bash
docker buildx build -t node-agent:debug -f build/Dockerfile.debug --load .
```

### Build with Custom Tag

```bash
docker buildx build -t quay.io/kubescape/node-agent:v1.0.0 -f build/Dockerfile --load .
```

## Using the Makefile

The project Makefile provides convenient build targets:

```bash
# Build binary only
make binary

# Build Docker image
make docker-build

# Build Docker image with gadgets
make docker-build  # This includes gadget building

# Push to registry
make docker-push

# Build all gadgets
make gadgets
```

## Build Prerequisites

- **Go 1.25+** - For building the binary
- **Docker** with buildx - For building container images
- **Linux** - Required for eBPF gadget compilation
- **Root/sudo** - Required for running gadget builds

## Build Arguments

The Dockerfile supports the following build arguments:

| Argument | Default | Description |
|----------|---------|-------------|
| `TARGETOS` | `linux` | Target operating system |
| `TARGETARCH` | `amd64` | Target architecture (amd64, arm64) |

Example:
```bash
docker buildx build \
  --build-arg TARGETARCH=arm64 \
  -t node-agent:arm64 \
  -f build/Dockerfile \
  --load .
```

## Image Variants

| Image | Dockerfile | Description |
|-------|------------|-------------|
| `node-agent:latest` | `Dockerfile` | Production image, minimal size |
| `node-agent:debug` | `Dockerfile.debug` | Includes debug tools (delve, shell) |

## Building Gadgets

NodeAgent uses image-based eBPF gadgets. To build all gadgets:

```bash
# Build all Kubescape gadgets
make gadgets

# Build a specific gadget
make -C ./pkg/ebpf/gadgets/exec build IMAGE=exec TAG=latest
```

The gadgets are packaged into `tracers.tar` and loaded at runtime.

## Troubleshooting

### Build fails with "permission denied"

Ensure Docker daemon is running and you have permissions:
```bash
sudo usermod -aG docker $USER
# Log out and back in
```

### Cross-compilation issues

For cross-platform builds, ensure QEMU is set up:
```bash
docker run --privileged --rm tonistiigi/binfmt --install all
```

### Out of disk space

Clean up Docker build cache:
```bash
docker builder prune -f
```

## See Also

- [Main README](../README.md)
- [Development Guide](../README.md#-development)
- [Makefile](../Makefile)