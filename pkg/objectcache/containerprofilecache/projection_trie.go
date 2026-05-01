package containerprofilecache

import "strings"

// trie implements a simple byte-level prefix trie for O(n) prefix matching
// where n is the length of the query string. Used by FieldSpec for prefix and
// suffix (reversed-insertion) matching.
type trie struct {
	children map[rune]*trie
	terminal bool // true if this node marks the end of an inserted pattern
}

func newTrie(patterns []string) *trie {
	root := &trie{}
	for _, p := range patterns {
		root.insert(p)
	}
	return root
}

func (t *trie) insert(pattern string) {
	cur := t
	for _, ch := range pattern {
		if cur.children == nil {
			cur.children = make(map[rune]*trie)
		}
		next, ok := cur.children[ch]
		if !ok {
			next = &trie{}
			cur.children[ch] = next
		}
		cur = next
	}
	cur.terminal = true
}

// HasMatch reports whether any inserted pattern is a prefix of s.
func (t *trie) HasMatch(s string) bool {
	cur := t
	if cur.terminal {
		return true // empty pattern matches everything
	}
	for _, ch := range s {
		next, ok := cur.children[ch]
		if !ok {
			return false
		}
		cur = next
		if cur.terminal {
			return true
		}
	}
	return false
}

// HasMatchSuffix reports whether any inserted pattern is a suffix of s.
// The trie must have been built with reversed patterns (via newSuffixTrie).
func (t *trie) HasMatchSuffix(s string) bool {
	return t.HasMatch(reverseString(s))
}

// newSuffixTrie builds a trie from reversed patterns so that HasMatchSuffix
// can perform suffix matching via forward traversal of the reversed query.
func newSuffixTrie(patterns []string) *trie {
	reversed := make([]string, len(patterns))
	for i, p := range patterns {
		reversed[i] = reverseString(p)
	}
	return newTrie(reversed)
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// containsMatch reports whether any pattern in the list is a substring of s.
// Linear scan; used only for Contains patterns (expected to be short lists).
func containsMatch(patterns []string, s string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
