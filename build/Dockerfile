FROM --platform=$BUILDPLATFORM golang:1.25-trixie AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH GOEXPERIMENT=greenteagc go build -o /out/node-agent -ldflags="-s -w" ./cmd/main.go

FROM gcr.io/distroless/static-debian13:latest

COPY --from=builder /out/node-agent /usr/bin/node-agent
COPY tracers.tar /root/tracers.tar
COPY configuration/ig-config.yaml /root/.ig/config.yaml

ARG image_version
ENV RELEASE=$image_version

WORKDIR /root
ENTRYPOINT ["node-agent"]
