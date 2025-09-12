package events

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

type OpenEvent struct {
	datasource.Data
	extra interface{}
}

func (event *OpenEvent) SetExtra(extra interface{}) {
	event.extra = extra
}

func (event *OpenEvent) GetExtra() interface{} {
	return event.extra
}

func (event *OpenEvent) GetPID() uint64 {
	d, _ := datasource.New(datasource.TypeSingle, "event") // FIXME this won't work
	pidF := d.GetField("proc.pid")
	pid, _ := pidF.Uint32(event.Data)
	return uint64(pid)
}
