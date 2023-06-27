FROM quay.io/kubescape/ebpf-engine:v1.0.0 as builder

FROM ubuntu:latest

RUN apt update && apt-get install wget git libelf-dev -y
RUN mkdir /etc/node-agent
RUN mkdir /etc/node-agent/resources
RUN mkdir /etc/node-agent/resources/ebpf
RUN mkdir /etc/node-agent/resources/ebpf/falco
RUN mkdir /etc/node-agent/configuration
RUN apt-get install ca-certificates -y
WORKDIR /etc/node-agent
RUN wget https://go.dev/dl/go1.20.2.linux-amd64.tar.gz 
RUN tar -xvf go1.20.2.linux-amd64.tar.gz  
RUN mv go /usr/local
ADD go.mod go.sum /etc/node-agent/
ENV GOROOT=/usr/local/go 
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH  
ENV GO111MODULE=on 
ENV CGO_ENABLED=0
RUN /usr/local/go/bin/go mod download
ADD . .
RUN /usr/local/go/bin/go build -o node-agent .

COPY --from=builder /etc/kubescape_ebpf_engine_sc/build/main /etc/node-agent/resources/ebpf/falco/userspace_app

ARG image_version
ENV RELEASE=$image_version

CMD ["./node-agent"]