package containerprofilecache

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sort"

	"github.com/kubescape/node-agent/pkg/objectcache"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

// suffixTrieMatcher wraps a reversed-pattern trie so it satisfies the
// objectcache.PathMatcher interface using HasMatchSuffix semantics.
type suffixTrieMatcher struct{ t *trie }

func (s *suffixTrieMatcher) HasMatch(str string) bool { return s.t.HasMatchSuffix(str) }

// CompileSpec unions ProfileDataRequired declarations from all rules into a
// single RuleProjectionSpec. Rules with nil ProfileDataRequired contribute
// nothing. Output is deterministic: pattern slices are sorted before hashing.
func CompileSpec(rules []typesv1.Rule) objectcache.RuleProjectionSpec {
	var spec objectcache.RuleProjectionSpec

	for i := range rules {
		r := &rules[i]
		if r.ProfileDataRequired == nil {
			continue
		}
		pdr := r.ProfileDataRequired
		mergeField(&spec.Opens, pdr.Opens)
		mergeField(&spec.Execs, pdr.Execs)
		mergeField(&spec.Capabilities, pdr.Capabilities)
		mergeField(&spec.Syscalls, pdr.Syscalls)
		mergeField(&spec.Endpoints, pdr.Endpoints)
		mergeField(&spec.EgressDomains, pdr.EgressDomains)
		mergeField(&spec.EgressAddresses, pdr.EgressAddresses)
		mergeField(&spec.IngressDomains, pdr.IngressDomains)
		mergeField(&spec.IngressAddresses, pdr.IngressAddresses)
	}

	// Sort and dedup all slice fields; build matchers.
	finalizeField(&spec.Opens)
	finalizeField(&spec.Execs)
	finalizeField(&spec.Capabilities)
	finalizeField(&spec.Syscalls)
	finalizeField(&spec.Endpoints)
	finalizeField(&spec.EgressDomains)
	finalizeField(&spec.EgressAddresses)
	finalizeField(&spec.IngressDomains)
	finalizeField(&spec.IngressAddresses)

	spec.Hash = hashSpec(&spec)
	return spec
}

// mergeField unions one rule's FieldRequirement into the accumulator FieldSpec.
func mergeField(dst *objectcache.FieldSpec, src typesv1.FieldRequirement) {
	if !src.Declared {
		return
	}
	dst.InUse = true
	if src.All {
		dst.All = true
		// Clear any previously accumulated selectors — they are dead under All
		// and would cause hash collisions between otherwise-equivalent specs.
		dst.Exact = nil
		dst.Prefixes = nil
		dst.Suffixes = nil
		dst.Contains = nil
		return
	}
	if dst.All {
		return // already all; narrower selectors from this rule are irrelevant
	}
	for _, p := range src.Patterns {
		switch {
		case p.Exact != "":
			if dst.Exact == nil {
				dst.Exact = make(map[string]struct{})
			}
			dst.Exact[p.Exact] = struct{}{}
		case p.Prefix != "":
			dst.Prefixes = append(dst.Prefixes, p.Prefix)
		case p.Suffix != "":
			dst.Suffixes = append(dst.Suffixes, p.Suffix)
		case p.Contains != "":
			dst.Contains = append(dst.Contains, p.Contains)
		}
	}
}

// finalizeField sorts, deduplicates slices, sets InUse, and builds matchers.
func finalizeField(f *objectcache.FieldSpec) {
	f.Prefixes = sortDedup(f.Prefixes)
	f.Suffixes = sortDedup(f.Suffixes)
	f.Contains = sortDedup(f.Contains)

	if !f.InUse {
		f.InUse = f.All || len(f.Exact) > 0 || len(f.Prefixes) > 0 || len(f.Suffixes) > 0 || len(f.Contains) > 0
	}

	if len(f.Prefixes) > 0 {
		f.PrefixMatcher = newTrie(f.Prefixes)
	}
	if len(f.Suffixes) > 0 {
		f.SuffixMatcher = &suffixTrieMatcher{t: newSuffixTrie(f.Suffixes)}
	}
}

func sortDedup(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}
	sort.Strings(ss)
	out := ss[:1]
	for _, s := range ss[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// hashSpec computes a deterministic FNV-64a hash over the spec's content.
// Each field contributes sorted, canonical bytes separated by NUL sentinels.
func hashSpec(s *objectcache.RuleProjectionSpec) string {
	h := fnv.New64a()
	fields := []*objectcache.FieldSpec{
		&s.Opens, &s.Execs, &s.Capabilities, &s.Syscalls, &s.Endpoints,
		&s.EgressDomains, &s.EgressAddresses, &s.IngressDomains, &s.IngressAddresses,
	}
	names := []string{
		"opens", "execs", "caps", "syscalls", "endpoints",
		"egressDomains", "egressAddrs", "ingressDomains", "ingressAddrs",
	}
	for i, f := range fields {
		_, _ = fmt.Fprintf(h, "%s\x00", names[i])
		if f.All {
			_, _ = h.Write([]byte("all\x00"))
		}
		exact := make([]string, 0, len(f.Exact))
		for k := range f.Exact {
			exact = append(exact, k)
		}
		sort.Strings(exact)
		for _, e := range exact {
			_, _ = fmt.Fprintf(h, "e:%s\x00", e)
		}
		for _, p := range f.Prefixes {
			_, _ = fmt.Fprintf(h, "p:%s\x00", p)
		}
		for _, s := range f.Suffixes {
			_, _ = fmt.Fprintf(h, "s:%s\x00", s)
		}
		for _, c := range f.Contains {
			_, _ = fmt.Fprintf(h, "c:%s\x00", c)
		}
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], h.Sum64())
	return fmt.Sprintf("%016x", binary.LittleEndian.Uint64(buf[:]))
}
