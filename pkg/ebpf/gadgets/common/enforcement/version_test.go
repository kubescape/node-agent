// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"testing"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type configGC struct {
	operators.GadgetContext
	config any
}

func (g configGC) GetVar(name string) (any, bool) {
	if name == "config" {
		return g.config, g.config != nil
	}
	return nil, false
}

func TestCheckBindingsVersion(t *testing.T) {
	v := viper.New()
	v.Set(bindingsVersionAnnotation, BindingsVersion)
	if err := checkBindingsVersion(configGC{config: v}); err != nil {
		t.Fatal(err)
	}
	for name, gc := range map[string]configGC{
		"other version": {config: func() *viper.Viper { o := viper.New(); o.Set(bindingsVersionAnnotation, "2"); return o }()},
		"no annotation": {config: viper.New()},
		"no metadata":   {},
	} {
		if err := checkBindingsVersion(gc); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}
