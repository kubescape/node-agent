FROM quay.io/kubescape/ebpf-engine:v1.0.0 as base

FROM golang:1.20-alpine as builder

ENV GO111MODULE=on 
ENV CGO_ENABLED=0

RUN mkdir /etc/node-agent
WORKDIR /etc/node-agent
ADD . .

RUN go build -o node-agent .

FROM alpine

RUN mkdir /etc/node-agent
RUN mkdir /etc/node-agent/resources
RUN mkdir /etc/node-agent/resources/ebpf
RUN mkdir /etc/node-agent/resources/ebpf/falco
RUN mkdir /etc/node-agent/configuration

WORKDIR /etc/node-agent

COPY --from=base /etc/kubescape_ebpf_engine_sc/build/main /etc/node-agent/resources/ebpf/falco/userspace_app
COPY --from=builder /etc/node-agent/node-agent ./node-agent


ARG image_version
ENV RELEASE=$image_version

CMD ["./node-agent"]