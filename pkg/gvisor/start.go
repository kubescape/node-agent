// Package gvisor receives a narrow subset of gVisor's SecCheck remote sink.
// The first supported signal is container/start. The wire message contains
// command arguments and a working directory, so only allowlisted identity
// fields may leave the decoder.
package gvisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// These values come from gVisor's SecCheck common.proto and container.proto
	// at 8a2c5049262ca84ea9c0981ac82eed02110d4ba7. The Linux trial must
	// confirm them against its pinned runsc build before this is enabled.
	protocolVersion = 1
	headerSize      = 8
	startMessage    = 1 // MESSAGE_CONTAINER_START in gVisor's common.proto
	maxFrameSize    = 1 << 20
	maxIDSize       = 256
)

// Start is the entire retained event. In particular, Args, Cwd, Env, and raw
// protobuf bytes must never be added to this type or passed to the callback.
type Start struct {
	Source      string
	ContainerID string
	ObservedAt  time.Time
	Dropped     uint32 // Cumulative sender-reported drop count on this connection.
}

// Resolver checks a claimed container ID against the local runtime inventory.
// The receiver never attributes an unverified claim to a Kubernetes workload.
type Resolver func(containerID string) bool

// StartHandler receives only runtime-verified start events.
type StartHandler func(Start)

func handshakeVersion(frame []byte) (uint64, error) {
	var version uint64
	for len(frame) > 0 {
		number, kind, n := protowire.ConsumeTag(frame)
		if n < 0 {
			return 0, errors.New("invalid handshake tag")
		}
		frame = frame[n:]
		if number == 1 && kind == protowire.VarintType {
			value, consumed := protowire.ConsumeVarint(frame)
			if consumed < 0 {
				return 0, errors.New("invalid handshake version")
			}
			version = value
			frame = frame[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, frame)
		if consumed < 0 {
			return 0, errors.New("invalid handshake field")
		}
		frame = frame[consumed:]
	}
	if version != protocolVersion {
		return 0, fmt.Errorf("unsupported remote sink version %d", version)
	}
	return version, nil
}

func decodeStartFrame(frame []byte, observedAt time.Time, resolve Resolver) (Start, bool, error) {
	if len(frame) < headerSize {
		return Start{}, false, errors.New("short remote sink header")
	}
	length := int(binary.LittleEndian.Uint16(frame[:2]))
	if length < headerSize || length > len(frame) {
		return Start{}, false, errors.New("invalid remote sink header size")
	}
	if binary.LittleEndian.Uint16(frame[2:4]) != startMessage {
		return Start{}, false, nil // Forward-compatible: skip other point types.
	}
	id, err := startID(frame[length:])
	if err != nil {
		return Start{}, false, err
	}
	if id == "" || resolve == nil || !resolve(id) {
		return Start{}, false, nil
	}
	return Start{
		Source:      "gvisor_trace",
		ContainerID: id,
		ObservedAt:  observedAt,
		Dropped:     binary.LittleEndian.Uint32(frame[4:8]),
	}, true, nil
}

func startID(payload []byte) (string, error) {
	var startID, contextID string
	for len(payload) > 0 {
		number, kind, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return "", errors.New("invalid start tag")
		}
		payload = payload[n:]
		if (number == 1 || number == 2) && kind == protowire.BytesType {
			value, consumed := protowire.ConsumeBytes(payload)
			if consumed < 0 {
				return "", errors.New("invalid start field")
			}
			if number == 1 {
				var err error
				contextID, err = contextContainerID(value)
				if err != nil {
					return "", err
				}
			} else {
				if len(value) > maxIDSize {
					return "", errors.New("start ID exceeds limit")
				}
				startID = string(value)
			}
			payload = payload[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, payload)
		if consumed < 0 {
			return "", errors.New("invalid start field")
		}
		payload = payload[consumed:]
	}
	if startID != "" && contextID != "" && startID != contextID {
		return "", errors.New("start and context container IDs differ")
	}
	if startID != "" {
		return startID, nil
	}
	return contextID, nil
}

func contextContainerID(payload []byte) (string, error) {
	var id string
	for len(payload) > 0 {
		number, kind, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return "", errors.New("invalid context tag")
		}
		payload = payload[n:]
		if number == 6 && kind == protowire.BytesType {
			value, consumed := protowire.ConsumeBytes(payload)
			if consumed < 0 || len(value) > maxIDSize {
				return "", errors.New("invalid context container ID")
			}
			id = string(value)
			payload = payload[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, payload)
		if consumed < 0 {
			return "", errors.New("invalid context field")
		}
		payload = payload[consumed:]
	}
	return id, nil
}
