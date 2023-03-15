FROM ubuntu:latest as builder

RUN apt update && apt install git curl llvm clang cmake make libelf-dev golang-go -y

RUN git clone https://github.com/kubescape/ebpf-engine /etc/kubescape_ebpf_engine_sc
WORKDIR /etc/kubescape_ebpf_engine_sc
RUN ./install_dependencies.sh
RUN mkdir build
WORKDIR /etc/kubescape_ebpf_engine_sc/build
RUN cmake ..
RUN make all

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /etc/node-agent
ADD . .
RUN go build -o node-agent .

FROM ubuntu:latest

RUN apt update
RUN apt-get install -y ca-certificates libelf-dev runc

RUN mkdir /etc/node-agent
RUN mkdir /etc/node-agent/configuration

COPY --from=builder /etc/kubescape_ebpf_engine_sc/build/main /etc/node-agent/resources/ebpf/falco/userspace_app
COPY --from=builder /etc/node-agent/node-agent /etc/node-agent/node-agent

WORKDIR /etc/node-agent
CMD [ "./node-agent" ]