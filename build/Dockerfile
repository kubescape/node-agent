FROM --platform=$BUILDPLATFORM golang:1.20-bullseye as builder

ENV GO111MODULE=on CGO_ENABLED=1
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN apt-get update && apt-get install -y \
    libseccomp-dev
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/node-agent .

FROM gcr.io/distroless/base-debian11:latest

#FIXME: need to support arm64
ARG ARCH=x86_64

COPY --from=builder /usr/lib/${ARCH}-linux-gnu/libseccomp.so* /usr/lib/${ARCH}-linux-gnu/
COPY --from=builder /out/node-agent /usr/bin/node-agent

ARG image_version
ENV RELEASE=$image_version

WORKDIR /root
ENTRYPOINT ["node-agent"]
