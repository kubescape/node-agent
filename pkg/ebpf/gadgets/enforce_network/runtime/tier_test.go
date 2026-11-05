// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/spf13/viper"
)

var errStop = errors.New("stop")

// configFor applies gadget.yaml and the parameter values the way Inspektor
// Gadget does for an image (custom parameter patches) and returns the result.
func configFor(t *testing.T, values api.ParamValues) *viper.Viper {
	t.Helper()
	metadata, err := os.ReadFile("../gadget.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var config *viper.Viper
	load := simple.New("load-metadata", simple.OnInit(func(gc operators.GadgetContext) error {
		if err := gc.(*gadgetcontext.GadgetContext).SetMetadata(metadata); err != nil {
			return err
		}
		value, _ := gc.GetVar("config")
		config = value.(*viper.Viper)
		return errStop
	}))
	gc := gadgetcontext.New(context.Background(), "enforce_network", gadgetcontext.WithDataOperators(load))
	if err := gc.Run(values); !errors.Is(err, errStop) {
		t.Fatalf("run: %v", err)
	}
	return config
}

func TestGadgetTiers(t *testing.T) {
	for _, c := range []struct {
		values api.ParamValues
		want   string
	}{
		{nil, TierLSM},
		{api.ParamValues{TierParam: TierLSM}, TierLSM},
		{api.ParamValues{TierParam: TierCgroup}, TierCgroup},
	} {
		got, err := effectiveTier(configFor(t, c.values))
		if err != nil || got != c.want {
			t.Errorf("%v: tier %q, %v; want %q", c.values, got, err, c.want)
		}
	}
}

func TestEffectiveTierRefusesMixedTiers(t *testing.T) {
	for _, c := range []struct {
		name    string
		enabled []string
	}{
		{"both", []string{"ig_net_connect", "ig_net_sendmsg", "ig_net_connect4", "ig_net_connect6", "ig_net_sendmsg4", "ig_net_sendmsg6"}},
		{"partial cgroup", []string{"ig_net_connect4", "ig_net_connect6", "ig_net_sendmsg4"}},
		{"partial lsm", []string{"ig_net_connect"}},
		{"none", nil},
	} {
		v := viper.New()
		for _, programs := range tierPrograms {
			for _, p := range programs {
				v.Set("programs."+p+".attach_to", disabledProgram)
			}
		}
		for _, p := range c.enabled {
			v.Set("programs."+p+".attach_to", "")
		}
		if tier, err := effectiveTier(v); err == nil {
			t.Errorf("%s: tier %q accepted", c.name, tier)
		} else if !strings.Contains(err.Error(), "tier") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
