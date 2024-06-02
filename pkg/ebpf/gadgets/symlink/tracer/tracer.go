//go:build !withoutebpf

package tracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" -type event symlink bpf/symlink.bpf.c -- -I./bpf/
