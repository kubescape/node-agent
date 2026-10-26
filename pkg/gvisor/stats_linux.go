//go:build linux

package gvisor

import "sync/atomic"

// Stats is a process-local diagnostic snapshot. During collection fields are
// read independently. After Run returns all receiver workers have finished.
// It contains no message payload, container identity or command arguments.
type Stats struct {
	AcceptedConnections uint64 `json:"accepted_connections"`
	RejectedConnections uint64 `json:"rejected_connections"`
	ClosedConnections   uint64 `json:"closed_connections"`
	Handshakes          uint64 `json:"handshakes"`
	HandshakeErrors     uint64 `json:"handshake_errors"`
	ReceivedFrames      uint64 `json:"received_frames"`
	ReadErrors          uint64 `json:"read_errors"`
	InterruptedReads    uint64 `json:"interrupted_reads"`
	InvalidFrames       uint64 `json:"invalid_frames"`
	UnresolvedStarts    uint64 `json:"unresolved_starts"`
	IgnoredFrames       uint64 `json:"ignored_frames"`
	VerifiedStarts      uint64 `json:"verified_starts"`
	CallbacksCompleted  uint64 `json:"callbacks_completed"`
	SenderDropFrames    uint64 `json:"sender_drop_frames"`
	QueueDrops          uint64 `json:"queue_drops"`
}

type receiverCounters struct {
	AcceptedConnections atomic.Uint64
	RejectedConnections atomic.Uint64
	ClosedConnections   atomic.Uint64
	Handshakes          atomic.Uint64
	HandshakeErrors     atomic.Uint64
	ReceivedFrames      atomic.Uint64
	ReadErrors          atomic.Uint64
	InterruptedReads    atomic.Uint64
	InvalidFrames       atomic.Uint64
	UnresolvedStarts    atomic.Uint64
	IgnoredFrames       atomic.Uint64
	VerifiedStarts      atomic.Uint64
	CallbacksCompleted  atomic.Uint64
	SenderDropFrames    atomic.Uint64
}

// Stats returns cumulative counts for this Receiver instance. A completed
// callback is not proof of successful output; callers must check their own I/O.
func (r *Receiver) Stats() Stats {
	return Stats{
		AcceptedConnections: r.counters.AcceptedConnections.Load(),
		RejectedConnections: r.counters.RejectedConnections.Load(),
		ClosedConnections:   r.counters.ClosedConnections.Load(),
		Handshakes:          r.counters.Handshakes.Load(),
		HandshakeErrors:     r.counters.HandshakeErrors.Load(),
		ReceivedFrames:      r.counters.ReceivedFrames.Load(),
		ReadErrors:          r.counters.ReadErrors.Load(),
		InterruptedReads:    r.counters.InterruptedReads.Load(),
		InvalidFrames:       r.counters.InvalidFrames.Load(),
		UnresolvedStarts:    r.counters.UnresolvedStarts.Load(),
		IgnoredFrames:       r.counters.IgnoredFrames.Load(),
		VerifiedStarts:      r.counters.VerifiedStarts.Load(),
		CallbacksCompleted:  r.counters.CallbacksCompleted.Load(),
		SenderDropFrames:    r.counters.SenderDropFrames.Load(),
		QueueDrops:          r.QueueDrops(),
	}
}
