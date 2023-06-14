FROM quay.io/kubescape/ebpf-engine:v1.0.0 as base

FROM golang:1.20-alpine as builder

# RUN apt update && apt-get install git libelf-dev golang-go -y

# RUN apt-get install ca-certificates -y

ENV GO111MODULE=on 

ENV CGO_ENABLED=0

RUN mkdir /etc/node-agent
WORKDIR /etc/node-agent
ADD . .

# ADD go.mod go.sum /etc/node-agent/
# RUN go mod download
# ADD . .
RUN go build -o node-agent .

FROM alpine

RUN mkdir /etc/node-agent
RUN mkdir /etc/node-agent/resources
RUN mkdir /etc/node-agent/resources/ebpf
RUN mkdir /etc/node-agent/resources/ebpf/falco
RUN mkdir /etc/node-agent/configuration

COPY --from=base /etc/kubescape_ebpf_engine_sc/build/main /etc/node-agent/resources/ebpf/falco/userspace_app
COPY --from=builder /work/build/gateway /usr/bin/gateway


ARG image_version
ENV RELEASE=$image_version

CMD ["./node-agent"]