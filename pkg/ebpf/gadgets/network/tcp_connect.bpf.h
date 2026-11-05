// Records the owner of each outgoing TCP connection in connect_owners.
// Included at the end of program.bpf.c, which defines the map.
#pragma once

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <gadget/filesystem.h>

#define NETWORK_AF_INET 2
#define NETWORK_AF_INET6 10

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct connect_owner));
} tmp_connect_owner SEC(".maps");

// ::ffff:a.b.c.d, an IPv4 peer reached through an IPv6 socket. Its packets are
// IPv4, so the key must be too.
static __always_inline bool is_v4_mapped(const struct in6_addr *a)
{
	return a->in6_u.u6_addr32[0] == 0 && a->in6_u.u6_addr32[1] == 0 &&
	       a->in6_u.u6_addr32[2] == bpf_htonl(0x0000ffff);
}

// tcp_connect() runs after the local port is chosen (inet_hash_connect) and
// sends the SYN itself, so the entry exists before the socket filter sees it.
SEC("kprobe/tcp_connect")
int BPF_KPROBE(ig_net_tcp_connect, struct sock *sk)
{
	struct connect_key key;
	__builtin_memset(&key, 0, sizeof(key));

	key.netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	key.rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	bool v4 = family == NETWORK_AF_INET;
	// The v6 fields exist only with CONFIG_IPV6; without it there are no
	// AF_INET6 sockets, and the guard keeps the program loadable.
	if (family == NETWORK_AF_INET6 &&
	    bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
		struct in6_addr laddr6, raddr6;
		BPF_CORE_READ_INTO(&raddr6, sk, __sk_common.skc_v6_daddr);
		if (is_v4_mapped(&raddr6)) {
			// tcp_v6_connect() hands mapped peers to tcp_v4_connect(),
			// which fills the IPv4 fields before calling tcp_connect().
			v4 = true;
		} else {
			BPF_CORE_READ_INTO(&laddr6, sk, __sk_common.skc_v6_rcv_saddr);
			key.version = 6;
			__builtin_memcpy(key.laddr, &laddr6, 16);
			__builtin_memcpy(key.raddr, &raddr6, 16);
		}
	} else if (!v4) {
		return 0;
	}
	if (v4) {
		__be32 laddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__be32 raddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		key.version = 4;
		__builtin_memcpy(key.laddr, &laddr, 4);
		__builtin_memcpy(key.raddr, &raddr, 4);
	}

	__u32 zero = 0;
	struct connect_owner *owner =
		bpf_map_lookup_elem(&tmp_connect_owner, &zero);
	if (!owner)
		return 0;

	// The scratch value is per CPU and reused: clear it so no bytes of an
	// earlier connect reach the map.
	__builtin_memset(owner, 0, sizeof(*owner));
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	owner->mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	owner->pid_tgid = bpf_get_current_pid_tgid();
	owner->uid_gid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&owner->task, sizeof(owner->task));
	if (parent) {
		bpf_probe_read_kernel(&owner->ptask, sizeof(owner->ptask),
				      parent->comm);
		owner->ppid = BPF_CORE_READ(parent, tgid);
		owner->ptid = BPF_CORE_READ(parent, pid);
	}

	// Kernel threads (e.g. the in-kernel CIFS client) have no mm.
	struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
	if (exe_file) {
		char *path = get_path_str(&exe_file->f_path);
		if (path)
			bpf_probe_read_kernel_str(&owner->exepath,
						  sizeof(owner->exepath), path);
	}

	bpf_map_update_elem(&connect_owners, &key, owner, BPF_ANY);
	return 0;
}
