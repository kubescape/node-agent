// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// The record of credentials the workload prepared, by address. A section adds
// it in its cred_prepare and cred_alloc_blank programs for a task of the
// workload (an armed task, or a task in a bound cgroup: an exec prepares its
// credentials before the task is armed) and deletes it in cred_free. A hook
// that meets overridden credentials (cred != real_cred) judges them when they
// are in the record: the workload prepared them, so they are its own (for
// example an io_uring request after a capset or under a personality, in an
// io-wq or SQPOLL worker or from task_work). Overlayfs copy-up overrides to
// the mounter's credentials, which the container runtime prepared: they are
// not in the record.
//
// The map is pinned, so a replacement instance keeps the record. Freed
// credentials leave it only when an LSM with a cred blob is active
// (security_cred_free skips the hooks otherwise); the supported kernels run
// SELinux and Landlock. A delete that fails leaves a stale address:
// credentials allocated there later are judged, never skipped. Credentials
// prepared before the binding are not recorded.

#ifndef __ENFORCEMENT_CREDS_H
#define __ENFORCEMENT_CREDS_H

#include <bpf/bpf_helpers.h>

#include "pin.h"

#define CRED_RECORD_MAX 65536

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CRED_RECORD_MAX);
	__type(key, __u64);
	__type(value, __u8);
	SANDBOX_PINNED;
} SANDBOX_MAP(creds) SEC(".maps");

// cred_recorded reports whether the workload prepared cred.
static __always_inline bool cred_recorded(const void *cred)
{
	__u64 key = (__u64)cred;

	return bpf_map_lookup_elem(&SANDBOX_MAP(creds), &key) != NULL;
}

// cred_record adds cred; false when the record is full.
static __always_inline bool cred_record(const void *cred)
{
	__u64 key = (__u64)cred;
	__u8 one = 1;

	return !bpf_map_update_elem(&SANDBOX_MAP(creds), &key, &one, BPF_ANY);
}

// cred_forget deletes cred, from cred_free.
static __always_inline void cred_forget(const void *cred)
{
	__u64 key = (__u64)cred;

	bpf_map_delete_elem(&SANDBOX_MAP(creds), &key);
}

#endif /* __ENFORCEMENT_CREDS_H */
