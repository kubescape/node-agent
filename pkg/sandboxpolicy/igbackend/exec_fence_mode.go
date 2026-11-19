package igbackend

import (
	"fmt"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// ExecFenceMode uses compiler-owned effective modes, including rule overrides.
// No policy means an authoritatively unselected child; callers must establish
// that the plan is complete before invoking this helper.
func ExecFenceMode(b sandboxpolicy.Binding, plan sandboxpolicy.Plan) (restartfence.Mode, error) {
	if len(plan.Policies) == 0 {
		return restartfence.Off, nil
	}
	policies, err := fullPolicies(b, plan)
	if err != nil {
		return 0, err
	}
	mode := restartfence.Audit
	for _, p := range policies {
		object, err := fullpolicy.CompileSharedPolicy(p)
		if err != nil {
			return 0, err
		}
		class, err := object.ExecutionClass()
		if err != nil {
			return 0, err
		}
		switch class {
		case 1:
		case 2:
			mode = restartfence.Strict
		default:
			return 0, fmt.Errorf("unknown compiled execution class %d", class)
		}
	}
	return mode, nil
}
