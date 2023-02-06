#!/bin/bash

sudo apt install git curl clang-12 -y

mkdir dependencies

git clone git@github.com:kubescape/kubescape-ebpf-engine.git dependencies/kubescape_ebpf_engine_sc
cd dependencies/kubescape_ebpf_engine_sc
./install_dependencies.sh
mkdir build && cd ./build
cmake ..
make all
cd ../../../
cp dependencies/kubescape_ebpf_engine_sc/dependencies/falco-libs/build/driver/bpf/probe.o ./resources/ebpf/kernel_obj.o
cp dependencies/kubescape_ebpf_engine_sc/build/main ./resources/ebpf/sniffer
