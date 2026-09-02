package storage

import (
	"context"
	"errors"
)

// ContainerProfileChecksumAnnotationKey is the ObjectMeta annotation under which
// a fetched ContainerProfile carries the content checksum of its body.
//
// CROSS-REPO CONTRACT — this exact string is part of an interface between
// repositories. A ProfileClient implementation that talks to a remote storage
// backend (today: armosec/private-node-agent's pkg/backend adapter) is
// responsible for re-keying whatever its own transport calls the checksum onto
// THIS key before returning the profile. The container-profile cache reads the
// validator from here and nowhere else.
//
// Changing this value fails silently rather than loudly: the cache simply never
// observes a checksum, every entry keeps an empty validator, and every fetch
// degrades to an unconditional one. Nothing breaks; the optimization just stops
// existing. Treat it as frozen.
//
// The key is deliberately namespaced under backend.kubescape.io so it cannot
// collide with the learning-lifecycle annotations in
// k8s-interface/instanceidhandler/v1/helpers, which the cache reads for status
// and completion.
const ContainerProfileChecksumAnnotationKey = "backend.kubescape.io/container-profile-checksum"

// ErrProfileUnchanged is returned by a ProfileClient implementation when the
// caller supplied a known checksum via WithKnownChecksum and the source
// confirmed the profile's content is byte-identical, so no body was
// transferred. There is no profile to return: the caller must keep the one it
// already holds.
//
// Implementations that cannot answer conditionally (for example the in-cluster
// CRD-backed client) never return this and need no knowledge of it.
var ErrProfileUnchanged = errors.New("container profile unchanged")

// knownChecksumKey is the unexported context key type for the known checksum,
// so no other package can collide with or forge the value.
type knownChecksumKey struct{}

// WithKnownChecksum returns a context carrying the content checksum of the
// ContainerProfile the caller already holds, as a hint that the body may be
// omitted if it still matches.
//
// It travels on the context rather than as a parameter because ProfileClient's
// signature must stay stable for its checksum-unaware implementers. A client
// that does not support conditional fetches ignores it and returns the body as
// usual, so attaching it is always safe.
//
// Attach it per call, never to a context shared by fetches of different
// objects: a checksum is a claim about one specific profile.
func WithKnownChecksum(ctx context.Context, checksum string) context.Context {
	return context.WithValue(ctx, knownChecksumKey{}, checksum)
}

// KnownChecksumFromContext returns the checksum attached by WithKnownChecksum,
// or "" when none was attached. "" means "send the body unconditionally".
func KnownChecksumFromContext(ctx context.Context) string {
	checksum, _ := ctx.Value(knownChecksumKey{}).(string)
	return checksum
}
