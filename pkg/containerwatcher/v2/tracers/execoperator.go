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

				if len(payload) == 0 {
					return fmt.Errorf("empty args")
				}

				argsSize, _ := argsSize.Uint32(data)
				if argsSize > uint32(len(payload)) {
					argsSize = uint32(len(payload))
				}
				argsCount, _ := argsCount.Int32(data)

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
