package types

import "github.com/armosec/armoapi-go/armotypes"

// The profileDataRequired schema (the type, its match patterns, and the custom
// JSON/YAML/BSON (un)marshalling) lives in armoapi-go/armotypes — the single
// module imported by every consumer: node-agent (this query side: projection /
// was_path_opened), storage (the generation side: rule-aware collapse), and the
// backend (rules persisted in MongoDB). Defining it once there guarantees the
// matcher can never drift between the side that records a profile and the side
// that queries it.
//
// These aliases preserve node-agent's historical type names. Note the shape
// change versus the old node-agent-local schema: a surface is now a *pointer*
// (ProfileDataRequired.Opens is *ProfileDataField); a nil pointer means "this
// rule does not declare this surface" — the role the old `Declared` bool played.
type (
	ProfileDataRequired = armotypes.ProfileDataRequired
	FieldRequirement    = armotypes.ProfileDataField
	PatternObject       = armotypes.ProfileDataPattern
)
