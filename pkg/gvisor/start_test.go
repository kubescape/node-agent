package gvisor

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func bytesField(number protowire.Number, value []byte) []byte {
	field := protowire.AppendTag(nil, number, protowire.BytesType)
	return protowire.AppendBytes(field, value)
}

func startFrame(id, contextID, canary string) []byte {
	context := bytesField(6, []byte(contextID))
	payload := bytesField(1, context)
	payload = append(payload, bytesField(2, []byte(id))...)
	payload = append(payload, bytesField(3, []byte("/work/"+canary))...)
	payload = append(payload, bytesField(4, []byte("--token="+canary))...)
	payload = append(payload, bytesField(5, []byte("KEY="+canary))...)
	frame := make([]byte, headerSize)
	binary.LittleEndian.PutUint16(frame[:2], headerSize)
	binary.LittleEndian.PutUint16(frame[2:4], startMessage)
	binary.LittleEndian.PutUint32(frame[4:8], 7)
	return append(frame, payload...)
}

func TestStartKeepsOnlyVerifiedIdentity(t *testing.T) {
	const canary = "synthetic-secret-do-not-retain"
	frame := startFrame("runtime-container-1", "runtime-container-1", canary)
	when := time.Now()
	event, ok, err := decodeStartFrame(frame, when, func(id string) bool { return id == "runtime-container-1" })
	if err != nil || !ok {
		t.Fatalf("verified start: ok=%t err=%v", ok, err)
	}
	if event.Source != "gvisor_trace" || event.ContainerID != "runtime-container-1" || event.Dropped != 7 || !event.ObservedAt.Equal(when) {
		t.Fatalf("unexpected retained event: %+v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) || strings.Contains(string(encoded), "token") {
		t.Fatalf("sensitive start fields escaped into retained event: %s", encoded)
	}
	_, ok, err = decodeStartFrame(frame, when, func(string) bool { return false })
	if err != nil || ok {
		t.Fatalf("unverified ID was accepted: ok=%t err=%v", ok, err)
	}
}

func TestStartRejectsConflictingAndMalformedIdentity(t *testing.T) {
	resolve := func(string) bool { return true }
	frame := startFrame("one", "two", "canary")
	if _, ok, err := decodeStartFrame(frame, time.Now(), resolve); err == nil || ok {
		t.Fatalf("conflicting IDs accepted: ok=%t err=%v", ok, err)
	}
	frame = startFrame(strings.Repeat("a", maxIDSize+1), "", "canary")
	if _, ok, err := decodeStartFrame(frame, time.Now(), resolve); err == nil || ok {
		t.Fatalf("oversized ID accepted: ok=%t err=%v", ok, err)
	}
	frame = startFrame("one", "one", "canary")
	frame[0] = 0xff
	if _, ok, err := decodeStartFrame(frame, time.Now(), resolve); err == nil || ok {
		t.Fatalf("invalid header accepted: ok=%t err=%v", ok, err)
	}
	frame = append(startFrame("one", "one", "canary"), 0xff)
	if _, ok, err := decodeStartFrame(frame, time.Now(), resolve); err == nil || ok {
		t.Fatalf("malformed trailing field accepted: ok=%t err=%v", ok, err)
	}
}

func TestUnknownPointIsSkipped(t *testing.T) {
	frame := startFrame("one", "one", "canary")
	binary.LittleEndian.PutUint16(frame[2:4], 999)
	if _, ok, err := decodeStartFrame(frame, time.Now(), func(string) bool { return true }); err != nil || ok {
		t.Fatalf("unknown point: ok=%t err=%v", ok, err)
	}
}

func TestHandshakeVersion(t *testing.T) {
	frame := protowire.AppendTag(nil, 1, protowire.VarintType)
	frame = protowire.AppendVarint(frame, 1)
	if _, err := handshakeVersion(frame); err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] = 2
	if _, err := handshakeVersion(frame); err == nil {
		t.Fatal("unsupported version accepted")
	}
}
