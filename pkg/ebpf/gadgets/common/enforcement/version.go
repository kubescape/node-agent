// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// BindingsVersion is the layout version of the binding map of ../bindings.h
// (struct sandbox_binding). A gadget declares it in its gadget.yaml
// annotation sandbox-bindings-version.
const BindingsVersion = "1"

const bindingsVersionAnnotation = "annotations.sandbox-bindings-version"

// checkBindingsVersion refuses a gadget whose binding layout version is not
// the one this controller writes (or that declares none).
func checkBindingsVersion(gc operators.GadgetContext) error {
	value, _ := gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	if !ok || metadata == nil {
		return fmt.Errorf("cannot check the binding layout: no gadget metadata")
	}
	if got := metadata.GetString(bindingsVersionAnnotation); got != BindingsVersion {
		return fmt.Errorf("gadget binding layout version %q, this controller writes %q", got, BindingsVersion)
	}
	return nil
}
