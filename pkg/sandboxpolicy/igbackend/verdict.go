package igbackend

import (
	"errors"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

type RawVerdict struct {
	Generation, Cgroup uint64
	Deny, Mode, PID    uint32
	PathResult         int32
	Path               string
}

func readVerdict(ds datasource.DataSource, data datasource.Data) (RawVerdict, error) {
	var r RawVerdict
	var errs [7]error
	r.Generation, errs[0] = ds.GetField("generation").Uint64(data)
	r.Cgroup, errs[1] = ds.GetField("cgroup").Uint64(data)
	r.Deny, errs[2] = ds.GetField("deny").Uint32(data)
	r.Mode, errs[3] = ds.GetField("mode").Uint32(data)
	r.PID, errs[4] = ds.GetField("host_pid").Uint32(data)
	r.PathResult, errs[5] = ds.GetField("path_result").Int32(data)
	r.Path, errs[6] = ds.GetField("path").String(data)
	return r, errors.Join(errs[:]...)
}
