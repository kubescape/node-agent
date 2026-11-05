// Native helper substitutes, compiled before ../../common/policy.h and
// ../../file_policy.h (see harness.c).
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#define __always_inline inline __attribute__((always_inline))
#define SEC(s)
#define __uint(name, value) int(*name)[value]
#define __type(name, value) value *name
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_F_NO_PREALLOC 1
#define BPF_F_RDONLY_PROG 128

struct file_slot;
struct file_literal_key;
static void *harness_lookup(void *map, const void *key);
#define bpf_map_lookup_elem(m, k) harness_lookup((void *)(m), (k))

static long bpf_loop(__u32 n, long (*fn)(__u64, void *), void *ctx, __u64 flags)
{
	(void)flags;
	for (__u32 i = 0; i < n; i++)
		if (fn(i, ctx))
			return i + 1;
	return n;
}
