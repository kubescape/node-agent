#!/bin/bash

sudo apt install git curl clang-12 -y

mkdir dependencies
pwd

git clone git@github.com:kubescape/ebpf-engine.git deps/dependencies/kubescape_ebpf_engine_sc
cd deps/dependencies/kubescape_ebpf_engine_sc
./install_dependencies.sh
mkdir build && cd ./build
cmake ..
make all
cd ../../../
cp deps/dependencies/kubescape_ebpf_engine_sc/deps/dependencies/falco-libs/build/driver/bpf/probe.o ../resources/ebpf/kernel_obj.o
cp deps/dependencies/kubescape_ebpf_engine_sc/build/main ../resources/ebpf/sniffer
