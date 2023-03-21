FROM quay.io/kubescape/sniffer:base as builder


FROM ubuntu:latest

RUN apt update && apt-get install git libelf-dev golang-go -y

RUN mkdir /etc/node-agent
RUN mkdir /etc/node-agent/resources
RUN mkdir /etc/node-agent/resources/ebpf
RUN mkdir /etc/node-agent/resources/ebpf/falco
RUN mkdir /etc/node-agent/configuration

COPY --from=builder /etc/kubescape_ebpf_engine_sc/build/main /etc/node-agent/resources/ebpf/falco/userspace_app

RUN apt-get install ca-certificates -y

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /etc/node-agent
RUN go build -o node-agent .

CMD ["./node-agent"]