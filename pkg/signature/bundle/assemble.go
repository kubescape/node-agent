//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"reflect"
	"sort"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// jsonKey is a stable dedup key for a value (deterministic struct field order).
func jsonKey(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// assembleSpec merges fragment specs (already in canonical order) into one
// effective spec. Append-then-dedup mirrors storage's merge discipline; string
// slices are deduped and sorted; ingress/egress merge by Identifier
// (later fragment wins); PolicyByRuleId and LabelSelector override-merge; scalar
// fields are last-writer-wins in fragment order (= class precedence).
func assembleSpec(frags []verifiedFragment) v1beta1.ContainerProfileSpec {
	out := v1beta1.ContainerProfileSpec{PolicyByRuleId: map[string]v1beta1.RulePolicy{}}
	matchLabels := map[string]string{}

	archSet := map[string]bool{}
	capSet := map[string]bool{}
	sysSet := map[string]bool{}
	seenExec := map[string]bool{}
	seenOpen := map[string]bool{}
	seenEndpoint := map[string]bool{}
	seenStack := map[string]bool{}

	ingressByID := map[string]v1beta1.NetworkNeighbor{}
	egressByID := map[string]v1beta1.NetworkNeighbor{}
	var ingressOrder, egressOrder []string

	for _, vf := range frags {
		s := vf.spec
		for _, a := range s.Architectures {
			archSet[a] = true
		}
		for _, c := range s.Capabilities {
			capSet[c] = true
		}
		for _, sc := range s.Syscalls {
			sysSet[sc] = true
		}
		for _, e := range s.Execs {
			if k := jsonKey(e); !seenExec[k] {
				seenExec[k] = true
				out.Execs = append(out.Execs, e)
			}
		}
		for _, o := range s.Opens {
			if k := jsonKey(o); !seenOpen[k] {
				seenOpen[k] = true
				out.Opens = append(out.Opens, o)
			}
		}
		for _, ep := range s.Endpoints {
			if k := jsonKey(ep); !seenEndpoint[k] {
				seenEndpoint[k] = true
				out.Endpoints = append(out.Endpoints, ep)
			}
		}
		for _, cs := range s.IdentifiedCallStacks {
			if k := jsonKey(cs); !seenStack[k] {
				seenStack[k] = true
				out.IdentifiedCallStacks = append(out.IdentifiedCallStacks, cs)
			}
		}
		for _, in := range s.Ingress {
			if _, ok := ingressByID[in.Identifier]; !ok {
				ingressOrder = append(ingressOrder, in.Identifier)
			}
			ingressByID[in.Identifier] = in
		}
		for _, eg := range s.Egress {
			if _, ok := egressByID[eg.Identifier]; !ok {
				egressOrder = append(egressOrder, eg.Identifier)
			}
			egressByID[eg.Identifier] = eg
		}
		for id, p := range s.PolicyByRuleId {
			out.PolicyByRuleId[id] = p
		}
		for k, v := range s.MatchLabels {
			matchLabels[k] = v
		}
		out.MatchExpressions = append(out.MatchExpressions, s.MatchExpressions...)
		if s.ImageID != "" {
			out.ImageID = s.ImageID
		}
		if s.ImageTag != "" {
			out.ImageTag = s.ImageTag
		}
		if !reflect.DeepEqual(s.SeccompProfile, v1beta1.SingleSeccompProfile{}) {
			out.SeccompProfile = s.SeccompProfile
		}
	}

	out.Architectures = sortedKeys(archSet)
	out.Capabilities = sortedKeys(capSet)
	out.Syscalls = sortedKeys(sysSet)
	for _, id := range ingressOrder {
		out.Ingress = append(out.Ingress, ingressByID[id])
	}
	for _, id := range egressOrder {
		out.Egress = append(out.Egress, egressByID[id])
	}
	if len(matchLabels) > 0 {
		out.MatchLabels = matchLabels
	}
	if len(out.PolicyByRuleId) == 0 {
		out.PolicyByRuleId = nil
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
