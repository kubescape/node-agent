//go:build linux

package main

import (
	"errors"
	"fmt"
	"strings"
)

// containerIDs is an exact allowlist for controlled trials, not a runtime
// inventory. Never accept prefixes or derive this list from receiver output.
type containerIDs map[string]struct{}

func (ids *containerIDs) Set(id string) error {
	if id == "" || len(id) > 256 || strings.ContainsAny(id, " \t\r\n") {
		return errors.New("container-id must be a nonempty exact runtime ID of at most 256 bytes without whitespace")
	}
	if *ids == nil {
		*ids = make(containerIDs)
	}
	(*ids)[id] = struct{}{}
	return nil
}

func (ids *containerIDs) String() string { return fmt.Sprintf("%d exact runtime IDs", len(*ids)) }

func (ids containerIDs) resolves(id string) bool {
	_, ok := ids[id]
	return ok
}
