package events

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type OpenEvent struct {
	datasource.Data
	extra interface{}
}

var _ utils.EnrichEvent = (*OpenEvent)(nil)

func (event *OpenEvent) GetBaseEvent() datasource.Data {
	return event.Data
}

func (event *OpenEvent) GetPID() uint64 {
	d, _ := datasource.New(datasource.TypeSingle, "event") // FIXME this won't work
	pidF := d.GetField("proc.pid")
	pid, _ := pidF.Uint32(event.Data)
	return uint64(pid)
}

func (event *OpenEvent) SetExtra(extra interface{}) {
	event.extra = extra
}

func (event *OpenEvent) GetExtra() interface{} {
	return event.extra
}

func (event *OpenEvent) GetPod() string {
	//TODO implement me
	panic("implement me")
}

func (event *OpenEvent) GetNamespace() string {
	//TODO implement me
	panic("implement me")
}

func (event *OpenEvent) GetTimestamp() types.Time {
	d, _ := datasource.New(datasource.TypeSingle, "event") // FIXME this won't work
	timeStampF := d.GetField("timestamp")
}
