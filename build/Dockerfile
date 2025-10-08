FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/node-agent -ldflags="-s -w" ./cmd/main.go

FROM --platform=$BUILDPLATFORM ghcr.io/inspektor-gadget/ig:v0.45.0 AS ig

RUN ["ig", "image", "pull", "trace_tcp:v0.45.0"]
RUN ["ig", "image", "pull", "advise_seccomp:v0.45.0"]
RUN ["ig", "image", "pull", "trace_capabilities:v0.45.0"]
RUN ["ig", "image", "pull", "trace_dns:v0.45.0"]
RUN ["ig", "image", "pull", "trace_exec:v0.45.0"]
RUN ["ig", "image", "pull", "trace_open:v0.45.0"]
RUN ["ig", "image", "export", "trace_tcp:v0.45.0", "advise_seccomp:v0.45.0", "trace_capabilities:v0.45.0", "trace_dns:v0.45.0", "trace_exec:v0.45.0", "trace_open:v0.45.0", "/tmp/tracers.tar"]

FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /out/node-agent /usr/bin/node-agent
COPY --from=ig /tmp/tracers.tar /root/tracers.tar
COPY configuration/ig-config.yaml /root/.ig/config.yaml

ARG image_version
ENV RELEASE=$image_version

WORKDIR /root
ENTRYPOINT ["node-agent"]
