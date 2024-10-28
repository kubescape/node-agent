FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN go install github.com/go-delve/delve/cmd/dlv@latest
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/node-agent .

FROM gcr.io/distroless/static-debian12:debug

COPY --from=builder /go/bin/dlv /usr/bin/dlv
COPY --from=builder /out/node-agent /usr/bin/node-agent

ARG image_version
ENV RELEASE=$image_version

WORKDIR /root
ENTRYPOINT ["/usr/bin/dlv", "--listen=:40000", "--headless=true", "--api-version=2", "--log", "exec", "/usr/bin/node-agent"]
