package main

import (
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	api.Info("init: hello from wasm")
	// Get the "raw" datasource (name used in the GADGET_TRACER macro)
	ds, err := api.GetDataSource("raw")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	// Get the field we're interested in
	dataF, err := ds.GetField("data")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	// Subscribe to all events from "raw" so we manipulate the data in the callback
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		d, err := dataF.String(data, 16384)
		if err != nil {
			api.Warnf("failed to get field data: %s", err)
			return
		}
		// Drop everything that doesn't contain "exec"
		if !strings.Contains(d, "exec") {
			return
		}

		// Only events that reach here will be emitted
		api.Infof("Data field: %s", d)
	}, 0)

	return 0
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	api.Info("start: hello from wasm")
	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	api.Info("stop: hello from wasm")
	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}
