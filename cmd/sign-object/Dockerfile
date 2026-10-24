FROM --platform=$BUILDPLATFORM golang:1.27-trixie AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /src
ARG TARGETOS TARGETARCH

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags experimental_signing -trimpath -ldflags="-s -w" -o /sign-object ./cmd/sign-object

# Small alpine base + su-exec (pinned by digest). The entrypoint drops to the
# owner of the bind-mounted /work, so `docker run -v "$PWD:/work" …` writes
# user-owned files with NO --user flag; sign-object never runs as root when a
# non-root /work is mounted.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
RUN apk add --no-cache su-exec
LABEL org.opencontainers.image.title="sign-object" \
      org.opencontainers.image.description="CLI to sign and verify Kubescape ApplicationProfile / NetworkNeighborhood / Rules objects (cosign, key-based or keyless)." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/kubescape/node-agent"
COPY --from=builder /sign-object /usr/local/bin/sign-object
COPY cmd/sign-object/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
