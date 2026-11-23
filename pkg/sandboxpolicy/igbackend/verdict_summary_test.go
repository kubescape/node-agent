package igbackend

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	sbxapi "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// A summary record names the rule from the generation's table, and the hook
// and detail from the gadget's enums; an unknown number stays a number.
func TestSummaryRecord(t *testing.T) {
	i := &nativeNodeInstance{section: "privilege"}
	i.tables.Store(uint64(5), slotTable{names: []string{"default", "p1/no-newns", "p1/no-uts"}})
	first := time.Unix(100, 0)
	r := i.summaryRecord(enforcement.VerdictSummary{Generation: 5, RuleID: 2, Hook: 2, Detail: 7, Enforce: true, RateLimited: true, FirstComm: "perl", LastComm: "perl", FirstPID: 4,
		CgroupID: 9, Slot: 1, Count: 1, First: first, Last: first})
	if r.Section != "privilege" || r.Rule != "p1/no-uts" || r.Hook != "capable" || r.Detail != "CAP_SETUID" || r.Mode != sbxapi.RuleEnforce ||
		r.Reason != "rate_limited" || r.FirstComm != "perl" || r.FirstPID != 4 || r.CgroupID != 9 || r.Count != 1 || !r.First.Equal(first) {
		t.Fatalf("record %+v", r)
	}
	r = i.summaryRecord(enforcement.VerdictSummary{Generation: 6, RuleID: 1, Hook: 40, Detail: 0xff | 1<<8})
	if r.Rule != "" || r.Hook != "hook 40" || r.Detail != "syscall unshare" || r.Mode != sbxapi.RuleAudit || r.Reason != "dropped" {
		t.Fatalf("unknown generation and hook %+v", r)
	}
}
