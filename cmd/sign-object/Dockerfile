FROM --platform=$BUILDPLATFORM golang:1.25-trixie AS builder

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
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /sign-object ./cmd/sign-object

FROM gcr.io/distroless/static-debian13:latest
COPY --from=builder /sign-object /usr/local/bin/sign-object
WORKDIR /work
ENTRYPOINT ["sign-object"]
