package tracers

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_exec/consts"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func NewExecOperator() operators.DataOperator {
	return simple.New("exec",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			ds, ok := gadgetCtx.GetDataSources()["exec"]
			if !ok {
				return fmt.Errorf("exec datasource not found")
			}

			argsF := ds.GetField("args")
			argsSize := ds.GetField("args_size")
			argsCount := ds.GetField("args_count")

			dataFunc := func(source datasource.DataSource, data datasource.Data) error {
				// Get all fields sent by ebpf
				payload, err := argsF.Bytes(data)
				if err != nil {
					return fmt.Errorf("failed to get args: %s", err)
				}

				argsSize, _ := argsSize.Uint32(data)
				argsCount, _ := argsCount.Int32(data)
				args := decodeExecArgs(payload, argsSize, argsCount)

				// TODO: The datasource doesn't support arrays yet, hence we have to
				// join the args in a single string. We are using a non-breaking space
				// as separator to avoid collisions with arguments that contain spaces.
				argsF.PutString(data, strings.Join(args, consts.ArgsSeparator))
				return nil
			}

			return ds.Subscribe(dataFunc, 0)
		}),
		simple.WithPriority(1),
	)
}

// decodeExecArgs splits the NUL-separated argv payload sent by the gadget. A
// trailing argument without a NUL (cut by the capture limit) is dropped. An
// empty payload (argv could not be read) yields no arguments rather than an
// error: the event is kept, the args field becomes "", GetArgs() returns nil,
// and consumers treat argv as unknown.
func decodeExecArgs(payload []byte, argsSize uint32, argsCount int32) []string {
	if argsSize > uint32(len(payload)) {
		argsSize = uint32(len(payload))
	}

	args := []string{}
	count := 0
	buf := []byte{}

	for i := 0; i < int(argsSize) && count < int(argsCount); i++ {
		c := payload[i]
		if c == 0 {
			args = append(args, string(buf))
			count = 0
			buf = []byte{}
		} else {
			buf = append(buf, c)
		}
	}
	return args
}
