// Native substitutes for the BPF helpers that ../../file_policy.h uses. The
// test (harness_test.go) compiles ../../common/policy.h and ../../file_policy.h
// unchanged apart from their includes, between harness_head and this main.
//
// Input: argv[1] is the compiled map content (uint32 slot count, the slots,
// uint32 literal count, the literal entries; little endian, as Go writes it).
// Each stdin line "slot fromImage path" prints the matched accept bits and,
// for each access kind and both guards, "rank rule_id is_default", then for
// each mask of masks (file_decide_mask) " | rank rule_id access".

_Static_assert(sizeof(struct file_slot) == 8696, "struct file_slot layout");
_Static_assert(sizeof(struct file_literal_key) == 16, "struct file_literal_key layout");
_Static_assert(sizeof(struct file_rule) == 112, "struct file_rule layout");
_Static_assert(sizeof(struct file_glob) == 56, "struct file_glob layout");

static char path_buf[FILE_BUF_SIZE + FILE_BUF_SLACK];
static struct file_match_state state;
static struct file_slot slots_data[FILE_MAX_SLOTS];
static __u32 nslots, nlits;
static struct lit {
	struct file_literal_key k;
	struct file_bits v;
} *lits;

static void *harness_lookup(void *map, const void *key)
{
	if (map == (void *)&file_slots) {
		__u32 i = *(const __u32 *)key;

		return i < nslots ? &slots_data[i] : NULL;
	}
	if (map == (void *)&file_literals) {
		const struct file_literal_key *k = key;

		for (__u32 i = 0; i < nlits; i++)
			if (lits[i].k.slot == k->slot && lits[i].k.hash == k->hash)
				return &lits[i].v;
		return NULL;
	}
	abort();
}

// The masks of harnessMasks (harness_test.go): a move source, a name of
// RENAME_EXCHANGE, a replacing and a new rename target, a hard link's name.
static const __u32 masks[5] = {
	FILE_MOVE_SOURCE_MASK,
	FILE_MOVE_SOURCE_MASK | FILE_REPLACED_MASK | FILE_NEW_NAME_GUARD_MASK,
	(1U << FILE_ACCESS_RENAME) | FILE_REPLACED_MASK | FILE_NEW_NAME_GUARD_MASK,
	(1U << FILE_ACCESS_RENAME) | FILE_NEW_FILE_MASK | FILE_NEW_NAME_GUARD_MASK,
	FILE_NEW_FILE_MASK | FILE_NEW_NAME_GUARD_MASK,
};

int main(int argc, char **argv)
{
	FILE *f;
	char line[8192];
	__u64 h = 0x0123456789abcdefULL;
	const char *v = "credentials";

	if (argc != 2 || !(f = fopen(argv[1], "rb")))
		return 2;
	if (fread(&nslots, 4, 1, f) != 1 || nslots > FILE_MAX_SLOTS ||
	    fread(slots_data, sizeof(struct file_slot), nslots, f) != nslots ||
	    fread(&nlits, 4, 1, f) != 1)
		return 3;
	lits = calloc(nlits + 1, sizeof(*lits));
	if (fread(lits, sizeof(*lits), nlits, f) != nlits)
		return 4;
	fclose(f);

	for (; *v; v++)
		h = file_hash_byte(h, *v);
	printf("hash %llx\n", (unsigned long long)h);

	while (fgets(line, sizeof(line), stdin)) {
		unsigned slot, fi;
		char *p;
		size_t len;
		struct file_bits out = {};
		const struct file_slot *s;

		if (sscanf(line, "%u %u", &slot, &fi) != 2)
			return 5;
		p = strchr(strchr(line, ' ') + 1, ' ') + 1;
		len = strcspn(p, "\n");
		memset(path_buf, 0x5a, sizeof(path_buf));
		memcpy(path_buf, p, len);
		s = file_slot_get(slot);
		if (!s) {
			printf("off\n");
			continue;
		}
		file_match(s, slot, path_buf, 0, len, &state, &out);
		printf("%llx %llx %llx %llx", (unsigned long long)out.w[0], (unsigned long long)out.w[1],
		       (unsigned long long)out.w[2], (unsigned long long)out.w[3]);
		for (__u32 a = 0; a <= FILE_ACCESS_NEW_NAME; a++) {
			struct policy_match m = {};

			file_decide(s, a, &out, fi, &m);
			printf(" %u %u %u", m.rank, m.rule_id, m.is_default);
		}
		for (int i = 0; i < 5; i++) {
			__u32 access = 0;
			struct policy_match m = {};

			file_decide_mask(s, masks[i], &out, fi, &m, &access);
			printf(" | %u %u %u", m.rank, m.rule_id, access);
		}
		printf("\n");
	}
	return 0;
}
