# Builder stage
FROM --platform=$BUILDPLATFORM golang:1.21-bullseye as builder

# Set environment variables
ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH
ARG BUILD_VERSION

# Build node-agent
COPY . /work/node-agent
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/node-agent .

# Build kube-host-sensor
COPY . /work/kube-host-sensor
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/kube-host-sensor --ldflags "-w -s -X main.BuildVersion=$BUILD_VERSION" .

# Final stage
FROM gcr.io/distroless/static-debian11:latest

# Copy built applications
COPY --from=builder /out/node-agent /usr/bin/node-agent
COPY --from=builder /out/kube-host-sensor /usr/bin/kube-host-sensor

# Set environment variables
ARG image_version
ENV RELEASE=$image_version

# Set up working directory
WORKDIR /root

# Define entrypoint
# NOTE: This needs to be adjusted if both applications can't run simultaneously
ENTRYPOINT ["node-agent"]