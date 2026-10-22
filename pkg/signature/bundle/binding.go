//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"errors"
	"fmt"

	rulebindingtypesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
)

var ErrBindingClassNotAllowed = errors.New("rule binding class not present in trust policy")

type BindingClassPolicy struct {
	Signers []string `json:"signers"`
}

func (p BindingClassPolicy) allowsSigner(id string) bool {
	for _, s := range p.Signers {
		if s == id {
			return true
		}
	}
	return false
}

type VerifiedBinding struct {
	Class  FragmentClass
	Signer string
}

type bindingEmbeddedView struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec rulebindingtypesv1.RuntimeAlertRuleBindingSpec `json:"spec"`
}

func AdmitBinding(b *rulebindingtypesv1.RuntimeAlertRuleBinding, policy TrustPolicy) (VerifiedBinding, error) {
	if b == nil {
		return VerifiedBinding{}, fmt.Errorf("nil RuntimeAlertRuleBinding object")
	}
	adapter := profiles.NewRuleBindingAdapter(b)
	if !signature.IsSigned(adapter) {
		return VerifiedBinding{}, fmt.Errorf("%w: %q", ErrFragmentUnsigned, b.Name)
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		if errors.Is(err, signature.ErrSignatureMismatch) {
			return VerifiedBinding{}, fmt.Errorf("%w: %q: %v", ErrFragmentTampered, b.Name, err)
		}
		return VerifiedBinding{}, fmt.Errorf("verify rule binding %q: %w", b.Name, err)
	}

	name := b.Name
	labels := b.Labels
	if embedded, present, embErr := signature.EmbeddedContent(adapter); present {
		if embErr != nil {
			return VerifiedBinding{}, fmt.Errorf("embedded content of %q: %w", b.Name, embErr)
		}
		var view bindingEmbeddedView
		if err := json.Unmarshal(embedded, &view); err != nil {
			return VerifiedBinding{}, fmt.Errorf("parse embedded content of %q: %w", b.Name, err)
		}
		name = view.Metadata.Name
		labels = view.Metadata.Labels
	}

	class := FragmentClass(labels[LabelFragmentClass])
	if class == "" {
		return VerifiedBinding{}, fmt.Errorf("%w: %q", ErrNoClass, name)
	}
	bpol, ok := policy.BindingClasses[class]
	if !ok {
		return VerifiedBinding{}, fmt.Errorf("%w: class %q (rule binding %q)", ErrBindingClassNotAllowed, class, name)
	}

	sig, err := signature.GetObjectSignature(adapter)
	if err != nil {
		return VerifiedBinding{}, fmt.Errorf("read signature of %q: %w", name, err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return VerifiedBinding{}, fmt.Errorf("signer identity of %q: %w", name, err)
	}
	if !bpol.allowsSigner(signer) {
		return VerifiedBinding{}, fmt.Errorf("%w: signer %q, class %q (rule binding %q)", ErrSignerNotTrusted, signer, class, name)
	}

	return VerifiedBinding{Class: class, Signer: signer}, nil
}

func BindingSignerID(b *rulebindingtypesv1.RuntimeAlertRuleBinding) (string, error) {
	sig, err := signature.GetObjectSignature(profiles.NewRuleBindingAdapter(b))
	if err != nil {
		return "", err
	}
	return signerIdentity(sig)
}
