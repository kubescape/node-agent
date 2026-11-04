// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import "fmt"

// Pattern is one parsed path glob. Placeholder: the gadget build replaces it.
type Pattern struct{}

// ParsePattern parses and normalises one path glob (see README "Patterns").
func ParsePattern(s string) (Pattern, error) {
	return Pattern{}, fmt.Errorf("not implemented")
}

// Compiled is the frozen map content plus the id tables events refer to.
// RuleNames[0] and Origins[0] are empty: id 0 means none. RuleNames[1] is
// "default", RuleNames[2] is "unresolved-path".
type Compiled struct {
	Generation uint64
	RuleNames  []string
	Origins    []string
}

// CompileKernel compiles one policy into slot 0.
func CompileKernel(d Document, generation uint64) (Compiled, error) {
	return CompileSlots([][]Document{{d}}, generation)
}

// CompileSlots compiles one node instance; each slot holds one combination of
// documents, merged by ../../common/merge/CONTRACT.md.
func CompileSlots(slots [][]Document, generation uint64) (Compiled, error) {
	return Compiled{}, fmt.Errorf("not implemented")
}
