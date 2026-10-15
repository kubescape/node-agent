package dedupcache

import (
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
)

// Reusable byte buffers for writing integers into the hash.
// These are stack-allocated per call via the fixed-size array trick.

func writeUint64(h *xxhash.Digest, v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	h.Write(buf[:])
}

func writeUint32(h *xxhash.Digest, v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	h.Write(buf[:])
}

func writeUint16(h *xxhash.Digest, v uint16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	h.Write(buf[:])
}

// writeString writes a length-prefixed string to the hash digest.
// The uint32 length prefix prevents collisions between adjacent variable-length strings
// (e.g. host="fo"+path="o/bar" vs host="foo"+path="/bar").
func writeString(h *xxhash.Digest, s string) {
	writeUint32(h, uint32(len(s)))
	h.WriteString(s)
}

// ComputeOpenKey computes a dedup key for open events.
func ComputeOpenKey(mntns uint64, pid uint32, path string, flagsRaw uint32) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, path)
	writeUint32(h, flagsRaw)
	return h.Sum64()
}

// ComputeNetworkKey computes a dedup key for network events.
func ComputeNetworkKey(mntns uint64, pid uint32, dstAddr string, dstPort uint16, proto string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, dstAddr)
	writeUint16(h, dstPort)
	writeString(h, proto)
	return h.Sum64()
}

// ComputeDNSKey computes a dedup key for DNS events forwarded to rule
// evaluation (queries and error responses). qr and qtype keep a query and its
// response, and an A and an AAAA lookup of the same name, from colliding; rcode
// (empty on a query) keeps a SERVFAIL from the first resolver and the NXDOMAIN
// from the retry distinct, so a rule gated on the response code sees the
// response it waits for; pid keeps alert attribution per process, as the open
// and network keys do.
func ComputeDNSKey(mntns uint64, pid uint32, dnsName string, qr string, qtype string, rcode string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, dnsName)
	writeString(h, qr)
	writeString(h, qtype)
	writeString(h, rcode)
	return h.Sum64()
}

// ComputeCapabilitiesKey computes a dedup key for capabilities events.
func ComputeCapabilitiesKey(mntns uint64, pid uint32, capability string, syscall string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, capability)
	writeString(h, syscall)
	return h.Sum64()
}

// ComputeHTTPKey computes a dedup key for HTTP events.
func ComputeHTTPKey(mntns uint64, pid uint32, direction string, method string, host string, path string, rawQuery string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, direction)
	writeString(h, method)
	writeString(h, host)
	writeString(h, path)
	writeString(h, rawQuery)
	return h.Sum64()
}

// ComputeSSHKey computes a dedup key for SSH events.
func ComputeSSHKey(mntns uint64, dstIP string, dstPort uint16) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeString(h, dstIP)
	writeUint16(h, dstPort)
	return h.Sum64()
}

// ComputeSymlinkKey computes a dedup key for symlink events.
func ComputeSymlinkKey(mntns uint64, pid uint32, oldPath string, newPath string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, oldPath)
	writeString(h, newPath)
	return h.Sum64()
}

// ComputeHardlinkKey computes a dedup key for hardlink events.
func ComputeHardlinkKey(mntns uint64, pid uint32, oldPath string, newPath string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, oldPath)
	writeString(h, newPath)
	return h.Sum64()
}

// ComputePtraceKey computes a dedup key for ptrace events.
func ComputePtraceKey(mntns uint64, pid uint32, exePath string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, exePath)
	return h.Sum64()
}

// ComputeSyscallKey computes a dedup key for syscall events.
func ComputeSyscallKey(mntns uint64, pid uint32, syscall string) uint64 {
	h := xxhash.New()
	writeUint64(h, mntns)
	writeUint32(h, pid)
	writeString(h, syscall)
	return h.Sum64()
}
