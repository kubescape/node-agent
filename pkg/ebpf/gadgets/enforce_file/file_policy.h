// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Policy maps, path matcher and decision of the file section. Nothing here
// reads a hook context or the current task, so a native test harness compiles
// this header unchanged (policy/harness_test.go). See ../common/policy.h for
// the ranks.
//
// Maps, written by the native owner and frozen before any binding:
// - file_slots:    slot -> header (generation, hash seed, mode), segment
//                  masks, glob table, rules and the merged default of each
//                  access kind.
// - file_literals: {slot, hash of a literal path component} -> the segment
//                  bits that the component matches.
//
// Matching is a shift-and NFA over path components. Every pattern of a slot
// owns consecutive segment bits (one per `/`-separated segment). For each
// component c of the path (D = active bits):
//
//   B  = literals[slot, h(c)] | wild | globs matching c
//   D' = (((D << 1) & ~first) | (first component ? first : 0)) & B | (D & star)
//   D' |= (D' << 1) & star & ~first      (a ** may match zero components)
//
// D starts at init (the leading ** bits); at the end, matched = D & accept.
// A rule matches when matched shares a bit with the rule's accept bits.
//
// h is FNV-1a 64 with the offset basis replaced by the slot's random seed. A
// glob segment pre*suf matches when the component is long enough, the hash of
// its first plen bytes equals the prefix hash and the hash of its last slen
// bytes, read backwards, equals the suffix hash.

#ifndef __FILE_POLICY_H
#define __FILE_POLICY_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "../common/policy.h"

#define FILE_MAX_SLOTS 64
#define FILE_SEG_BITS 256
#define FILE_SEG_WORDS 4
#define FILE_MAX_RULES 64
#define FILE_MAX_GLOBS 16
#define FILE_MAX_LITERALS 16384
#define FILE_GLOB_PART_MAX 16
// Policies per slot: a bit mask in struct file_slot.
#define FILE_MAX_DOCS 32

// Longest path judged, without the trailing NUL; longer is unresolved.
#define FILE_PATH_MAX 4096
#define FILE_NAME_MAX 255
// Path buffer: bpf_d_path writes from offset 0, the dentry walk writes
// backwards and ends at FILE_BUF_SIZE - 1 (a NUL). FILE_BUF_SLACK keeps every
// masked offset plus one name inside the buffer.
#define FILE_BUF_SIZE 8192
#define FILE_BUF_MASK (FILE_BUF_SIZE - 1)
#define FILE_BUF_SLACK 512

#define FILE_FNV_PRIME 0x100000001b3ULL

// Access kinds; the value is the bit index in a rule's access mask and the
// index of the per-access arrays.
enum file_access : __u32 {
	FILE_ACCESS_READ = 0,
	FILE_ACCESS_WRITE = 1,
	FILE_ACCESS_CREATE = 2,
	FILE_ACCESS_DELETE = 3,
	FILE_ACCESS_RENAME = 4,
	FILE_ACCESS_CHMOD = 5,
	// Events and unresolved ranks only: the move-source guard and the
	// new-name guard.
	FILE_ACCESS_MOVE_SOURCE = 6,
	FILE_ACCESS_NEW_NAME = 7,
};
#define FILE_ACCESS_KINDS 6

// Rule flags.
#define FILE_RULE_FROM_IMAGE 1 // only files of the image's lower layer
#define FILE_RULE_ANY_PATH 2 // no paths: every path
// A deny rule of read or write whose patterns have parent directories: its
// guard (those parents) protects move sources.
#define FILE_RULE_GUARD 4
// A deny rule of write or create whose patterns have parent directories: the
// same guard protects new names (a directory moved or linked onto a parent).
#define FILE_RULE_NEW_NAME_GUARD 8

// Slot flags, set by the owner (not the compiler).
// The owner verified the overlay inode layout that fromImage reads; without
// it no file is an image file.
#define FILE_SLOT_FROM_IMAGE 1

// Access kinds judged on a move source (the old name of a rename or a hard
// link, both names of RENAME_EXCHANGE): rename, read and write with the full
// decision, and the guard. A new name gives the file's content to whoever can
// use that name, so it is a read and a write of the file.
#define FILE_MOVE_SOURCE_MASK                                                  \
	((1U << FILE_ACCESS_READ) | (1U << FILE_ACCESS_WRITE) |                \
	 (1U << FILE_ACCESS_RENAME) | (1U << FILE_ACCESS_MOVE_SOURCE))
// A name whose file is replaced (the new name of a replacing rename, both
// names of RENAME_EXCHANGE) is also a write and a delete.
#define FILE_REPLACED_MASK ((1U << FILE_ACCESS_WRITE) | (1U << FILE_ACCESS_DELETE))
// A new name that does not exist yet (of a rename or a hard link) gives that
// name the file's content: a create and a write.
#define FILE_NEW_FILE_MASK ((1U << FILE_ACCESS_CREATE) | (1U << FILE_ACCESS_WRITE))
// Every new name of a rename, a hard link or a symbolic link (both names of
// RENAME_EXCHANGE) is also judged against the new-name guard.
#define FILE_NEW_NAME_GUARD_MASK (1U << FILE_ACCESS_NEW_NAME)

#define FILE_RULE_ID_DEFAULT 1
#define FILE_RULE_ID_UNRESOLVED 2

struct file_bits {
	__u64 w[FILE_SEG_WORDS];
};

struct file_glob {
	struct file_bits bits; // segments that are this glob
	__u64 pre_hash;
	__u64 suf_hash;
	__u8 pre_len;
	__u8 suf_len;
	__u8 pad[6];
};

struct file_rule {
	struct file_bits match; // accept bits of the rule's paths
	struct file_bits except; // accept bits of its except paths
	struct file_bits guard; // accept bits of its guard (FILE_RULE_GUARD)
	__u32 rule_id;
	__u32 origin_id;
	__u8 access; // bit per enum file_access
	__u8 rank; // enum policy_rank
	__u8 doc; // index of the rule's policy in the slot
	__u8 flags; // FILE_RULE_*
	__u32 pad;
};

struct file_slot {
	__u64 generation;
	__u64 seed; // hash offset basis of this slot
	__u32 mode; // 0: the slot is not judged
	__u32 nrules;
	__u32 nglobs;
	__u32 flags; // FILE_SLOT_*
	struct file_bits first, star, wild, accept, init;
	// Merged default per access kind (rule_id 1).
	struct policy_value defaults[FILE_ACCESS_KINDS];
	// Bit i: policy i of the slot has an enforce default deny for that
	// access kind (merge rule 5).
	__u32 deny_enforce_docs[FILE_ACCESS_KINDS];
	// Rank when the path cannot be resolved, per enum file_access
	// (including both guards): the most limiting rule or default.
	__u8 unresolved[8];
	// Per enum file_access: 1 when a rule without paths judges it (never
	// for a guard), and the union of the accept bits its rules match (the
	// guard bits for a guard). No shared bit and no such rule: no rule can
	// match, the rules are not scanned.
	__u8 any_path[8];
	struct file_bits rule_union[8];
	struct file_glob globs[FILE_MAX_GLOBS];
	struct file_rule rules[FILE_MAX_RULES];
};

struct file_literal_key {
	__u32 slot;
	__u32 pad;
	__u64 hash;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FILE_MAX_SLOTS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct file_slot);
} file_slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FILE_MAX_LITERALS);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, struct file_literal_key);
	__type(value, struct file_bits);
} file_literals SEC(".maps");

// file_slot_get returns the slot header, or NULL when the slot is not judged.
static __always_inline const struct file_slot *file_slot_get(__u32 slot)
{
	const struct file_slot *s = bpf_map_lookup_elem(&file_slots, &slot);

	if (!s || s->mode == POLICY_MODE_OFF)
		return NULL;
	return s;
}

/* Matcher */

// Per-CPU matcher state, kept out of the 512-byte stack. The counters live
// here, not in the bpf_loop context on the stack: the verifier then sees them
// as unknown values and the callback's states converge.
struct file_match_state {
	__u64 pre[FILE_GLOB_PART_MAX + 1]; // forward hash after k bytes
	__u64 suf[FILE_GLOB_PART_MAX + 1]; // backward hash of the last k bytes
	struct file_bits d;
	struct file_bits b;
	__u64 h; // hash of the current component so far
	__u32 comp; // offset of the current component's first byte
	__u32 inlen; // bytes of the current component so far
	__u32 first; // 1 until the first component is consumed
	__u32 pad;
};

// bpf_loop needs its context on the stack: pointers and fixed values only.
struct file_match_ctx {
	const struct file_slot *s;
	const char *buf; // FILE_BUF_SIZE + FILE_BUF_SLACK bytes
	struct file_match_state *st;
	__u32 slot;
	__u32 start; // first byte of the path ('/')
	__u32 len; // path length, no NUL
	__u32 pad;
};

static __always_inline __u64 file_hash_byte(__u64 h, __u8 c)
{
	return (h ^ c) * FILE_FNV_PRIME;
}

// Hashes the last bytes of a component backwards: suf[k] for k <= 16.
struct file_suf_ctx {
	const char *buf;
	struct file_match_state *st;
	__u64 h;
	__u32 last; // offset of the component's last byte
	__u32 inlen;
};

static long file_suf_step(__u64 i, void *ctx)
{
	struct file_suf_ctx *c = ctx;

	if (i >= c->inlen || i >= FILE_GLOB_PART_MAX)
		return 1;
	c->h = file_hash_byte(c->h, c->buf[(c->last - i) & FILE_BUF_MASK]);
	c->st->suf[i + 1] = c->h;
	return 0;
}

struct file_glob_ctx {
	const struct file_slot *s;
	struct file_match_state *st;
	__u32 inlen;
};

static long file_glob_step(__u64 i, void *ctx)
{
	struct file_glob_ctx *c = ctx;
	const struct file_glob *g;
	__u32 pl, sl;

	if (i >= c->s->nglobs || i >= FILE_MAX_GLOBS)
		return 1;
	g = &c->s->globs[i & (FILE_MAX_GLOBS - 1)];
	pl = g->pre_len;
	sl = g->suf_len;
	if (pl > FILE_GLOB_PART_MAX || sl > FILE_GLOB_PART_MAX ||
	    pl + sl > c->inlen)
		return 0;
	if (c->st->pre[pl] != g->pre_hash || c->st->suf[sl] != g->suf_hash)
		return 0;
	for (int w = 0; w < FILE_SEG_WORDS; w++)
		c->st->b.w[w] |= g->bits.w[w];
	return 0;
}

// file_component consumes one complete component of inlen bytes.
static __always_inline void file_component(struct file_match_ctx *c)
{
	const struct file_slot *s = c->s;
	struct file_match_state *st = c->st;
	struct file_literal_key key = { .slot = c->slot, .hash = st->h };
	const struct file_bits *lit;
	__u64 carry, prev;
	int i;

	lit = bpf_map_lookup_elem(&file_literals, &key);
	for (i = 0; i < FILE_SEG_WORDS; i++)
		st->b.w[i] = s->wild.w[i] | (lit ? lit->w[i] : 0);

	if (s->nglobs) {
		struct file_suf_ctx sc = {
			.buf = c->buf,
			.st = st,
			.h = s->seed,
			.last = c->start + st->comp + st->inlen - 1,
			.inlen = st->inlen,
		};
		struct file_glob_ctx gc = { .s = s, .st = st, .inlen = st->inlen };

		st->suf[0] = s->seed;
		bpf_loop(FILE_GLOB_PART_MAX, file_suf_step, &sc, 0);
		bpf_loop(FILE_MAX_GLOBS, file_glob_step, &gc, 0);
	}

	// D' = (((D << 1) & ~first) | (first component ? first : 0)) & B
	//      | (D & star)
	prev = 0;
	for (i = 0; i < FILE_SEG_WORDS; i++) {
		__u64 d = st->d.w[i];
		__u64 shl = (d << 1) | prev;

		prev = d >> 63;
		shl &= ~s->first.w[i];
		if (st->first)
			shl |= s->first.w[i];
		st->d.w[i] = (shl & st->b.w[i]) | (d & s->star.w[i]);
	}
	// D' |= (D' << 1) & star & ~first
	carry = 0;
	for (i = 0; i < FILE_SEG_WORDS; i++) {
		__u64 d = st->d.w[i];
		__u64 shl = (d << 1) | carry;

		carry = d >> 63;
		st->d.w[i] = d | (shl & s->star.w[i] & ~s->first.w[i]);
	}
	st->first = 0;
}

// file_match_step handles byte i of the path; i == len ends the path.
static long file_match_step(__u64 i, void *ctx)
{
	struct file_match_ctx *c = ctx;
	struct file_match_state *st = c->st;
	__u8 ch = 0;
	__u32 k;

	if (i < c->len)
		ch = c->buf[(c->start + i) & FILE_BUF_MASK];
	if (i >= c->len || ch == '/') {
		if (st->inlen)
			file_component(c);
		if (i >= c->len)
			return 1;
		st->comp = i + 1;
		st->inlen = 0;
		st->h = c->s->seed;
		st->pre[0] = st->h;
		return 0;
	}
	st->h = file_hash_byte(st->h, ch);
	k = ++st->inlen;
	if (k <= FILE_GLOB_PART_MAX)
		st->pre[k] = st->h;
	return 0;
}

// file_match fills out with the accept bits of every pattern that matches
// the len-byte path at buf[start]. len is at most FILE_PATH_MAX.
static __always_inline void file_match(const struct file_slot *s, __u32 slot,
				       const char *buf, __u32 start, __u32 len,
				       struct file_match_state *st,
				       struct file_bits *out)
{
	struct file_match_ctx c = {
		.s = s,
		.buf = buf,
		.st = st,
		.slot = slot,
		.start = start,
		.len = len,
	};

	st->d = s->init;
	st->h = s->seed;
	st->pre[0] = s->seed;
	st->comp = 0;
	st->inlen = 0;
	st->first = 1;
	bpf_loop(FILE_PATH_MAX + 1, file_match_step, &c, 0);
	for (int i = 0; i < FILE_SEG_WORDS; i++)
		out->w[i] = st->d.w[i] & s->accept.w[i];
}

/* Decision */

static __always_inline bool file_bits_any(const struct file_bits *a,
					  const struct file_bits *b)
{
	__u64 x = 0;

	for (int i = 0; i < FILE_SEG_WORDS; i++)
		x |= a->w[i] & b->w[i];
	return x != 0;
}

struct file_decide_ctx {
	const struct file_slot *s;
	const struct file_bits *matched;
	__u32 access_bit; // 0 for a guard
	__u32 docs; // policies with a matching rule
	__u8 from_image;
	__u8 allowed;
	// The FILE_RULE_* flag of the guard. In the padding: a larger context
	// doubles the instructions the verifier processes.
	__u8 guard_flag;
	struct policy_match m;
};

static long file_rule_step(__u64 i, void *ctx)
{
	struct file_decide_ctx *c = ctx;
	const struct file_rule *r;
	bool hit;

	if (i >= c->s->nrules || i >= FILE_MAX_RULES)
		return 1;
	r = &c->s->rules[i & (FILE_MAX_RULES - 1)];
	if (c->access_bit) {
		if (!(r->access & c->access_bit))
			return 0;
		hit = (r->flags & FILE_RULE_ANY_PATH) ||
		      file_bits_any(c->matched, &r->match);
	} else {
		if (!(r->flags & c->guard_flag))
			return 0;
		hit = file_bits_any(c->matched, &r->guard);
	}
	if (!hit || file_bits_any(c->matched, &r->except))
		return 0;
	if ((r->flags & FILE_RULE_FROM_IMAGE) && !c->from_image)
		return 0;
	c->docs |= 1U << (r->doc & 31);
	if (r->rank == POLICY_RANK_ALLOW)
		c->allowed = 1;
	if (r->rank > c->m.rank) {
		c->m.rank = r->rank;
		c->m.is_default = 0;
		c->m.rule_id = r->rule_id;
		c->m.origin_id = r->origin_id;
	}
	return 0;
}

// file_decide resolves one access kind (or a guard: FILE_ACCESS_MOVE_SOURCE,
// FILE_ACCESS_NEW_NAME) of a matched path into m: the most limiting matching
// rule, else the access kind's default. When every matching rule denies, the
// enforce default deny of each policy without a matching rule still applies
// (merge rule 5). A guard has no default.
static __always_inline void file_decide(const struct file_slot *s,
					__u32 access,
					const struct file_bits *matched,
					bool from_image,
					struct policy_match *m)
{
	struct file_decide_ctx c = {
		.s = s,
		.matched = matched,
		.access_bit = access < FILE_ACCESS_KINDS ? 1U << access : 0,
		.guard_flag = access == FILE_ACCESS_NEW_NAME ?
				      FILE_RULE_NEW_NAME_GUARD :
				      FILE_RULE_GUARD,
		.from_image = from_image,
	};
	__u32 a = access < FILE_ACCESS_KINDS ? access : 0;

	if (s->any_path[access & 7] ||
	    file_bits_any(matched, &s->rule_union[access & 7]))
		bpf_loop(FILE_MAX_RULES, file_rule_step, &c, 0);
	if (access >= FILE_ACCESS_KINDS) {
		*m = c.m;
		return;
	}
	if (c.m.rank == POLICY_RANK_NONE) {
		policy_take(&c.m, &s->defaults[a], true);
	} else if (!c.allowed && (s->deny_enforce_docs[a] & ~c.docs) &&
		   c.m.rank < POLICY_RANK_DENY_ENFORCE) {
		c.m.rank = POLICY_RANK_DENY_ENFORCE;
		c.m.is_default = 1;
		c.m.rule_id = s->defaults[a].rule_id;
		c.m.origin_id = s->defaults[a].origin_id;
	}
	*m = c.m;
}

// file_decide_mask resolves every access kind in mask (bits of enum
// file_access, with the guards) and keeps the most limiting result in m and
// the access kind that gave it in access. m starts empty.
static __always_inline void file_decide_mask(const struct file_slot *s,
					     __u32 mask,
					     const struct file_bits *matched,
					     bool from_image,
					     struct policy_match *m,
					     __u32 *access)
{
	for (__u32 a = 0; a <= FILE_ACCESS_NEW_NAME; a++) {
		struct policy_match x = {};

		if (!(mask & (1U << a)))
			continue;
		file_decide(s, a, matched, from_image, &x);
		if (x.rank > m->rank) {
			*m = x;
			*access = a;
		}
	}
}

// file_unresolved fills m for a path that cannot be resolved: the most
// limiting rule or default of the access kind (fail closed).
static __always_inline void file_unresolved(const struct file_slot *s,
					    __u32 access,
					    struct policy_match *m)
{
	m->rank = s->unresolved[access & 7];
	m->is_default = 0;
	m->rule_id = FILE_RULE_ID_UNRESOLVED;
	m->origin_id = 0;
}

#endif /* __FILE_POLICY_H */
