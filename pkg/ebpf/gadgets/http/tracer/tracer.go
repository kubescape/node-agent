package tracer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type active_connection_info -type packet_buffer -type httpevent -type debug_event http_sniffer bpf/http-sniffer.c -- -I./bpf/
const (
	EVENT_TYPE_CONNECT = iota
	EVENT_TYPE_ACCEPT
	EVENT_TYPE_REQUEST
	EVENT_TYPE_RESPONSE
	EVENT_TYPE_CLOSE
)

type Tracer struct {
	*networktracer.Tracer[types.Event]

	cancel context.CancelFunc
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.install(); err != nil {
		t.Close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
}

func (t *Tracer) Close() {
	if t.cancel != nil {
		t.cancel()
	}

	if t.Tracer != nil {
		t.Tracer.Close()
	}
}

func (t *Tracer) install() error {
	networkTracer, err := networktracer.NewTracer[types.Event]()
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
	}
	t.Tracer = networkTracer
	return nil
}

func (t *Tracer) RunWorkaround() error {
	if err := t.run(); err != nil {
		t.Close()
		return fmt.Errorf("running tracer: %w", err)
	}
	return nil
}

func (t *Tracer) run() error {
	spec, err := loadHttp_sniffer()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := t.Tracer.Run(spec, types.Base, t.parseHTTP); err != nil {
		return fmt.Errorf("setting network tracer spec: %w", err)
	}

	return nil
}

func (t *Tracer) parseHTTP(rawSample []byte, netns uint64) (*types.Event, error) {
	bpfEvent := (*http_snifferHttpevent)(unsafe.Pointer(&rawSample[0]))

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, bpfEvent.OtherIp)

	httpData, err := getHttpData(bpfEvent)
	if err != nil {
		return nil, err
	}

	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: uint64(bpfEvent.Netns)},
		Pid:           bpfEvent.Pid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		Syscall:       string(bpfEvent.Syscall[:]),
		OtherPort:     bpfEvent.OtherPort,
		OtherIp:       ip.String(),
		Headers:       httpData,
	}

	return &event, nil
}

func getHttpData(bpfEvent *http_snifferHttpevent) (types.HTTPData, error) {
	switch bpfEvent.Type {
	case EVENT_TYPE_REQUEST:
		httpData, err := parseHTTPRequest(FromCString(bpfEvent.Buf[:]))
		if err != nil {
			return nil, err
		}
		return httpData, nil
	case EVENT_TYPE_RESPONSE:
		httpData, err := parseHTTPResponse(FromCString(bpfEvent.Buf[:]))
		if err != nil {
			return nil, err
		}
		return httpData, nil
	default:
		return nil, fmt.Errorf("unknown event type: %d", bpfEvent.Type)
	}

}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{}
	return tracer, nil
}
