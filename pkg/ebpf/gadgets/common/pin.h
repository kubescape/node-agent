// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Pinned state of a long-lived enforcement instance. The maps that hold the
// section's state (bindings, slot state, policy, task marks, fault counters)
// are pinned by name, so the next load of the same gadget re-opens them: a
// restart keeps the state, with no re-binding and no re-arming. The loader
// pins under one directory for every gadget, so each section gives its maps
// a unique prefix: define SANDBOX_SECTION (for example sbx_priv_) before the
// common headers.

#ifndef __ENFORCEMENT_PIN_H
#define __ENFORCEMENT_PIN_H

#include <bpf/bpf_helpers.h>

#ifndef SANDBOX_SECTION
#error "define SANDBOX_SECTION, the name prefix of the section's pinned maps"
#endif

#define SANDBOX_CAT2(a, b) a##b
#define SANDBOX_CAT(a, b) SANDBOX_CAT2(a, b)

// SANDBOX_MAP is the name of a pinned map of the section.
#define SANDBOX_MAP(name) SANDBOX_CAT(SANDBOX_SECTION, name)

// SANDBOX_PINNED marks a map definition as pinned by name.
#define SANDBOX_PINNED __uint(pinning, LIBBPF_PIN_BY_NAME)

#endif /* __ENFORCEMENT_PIN_H */
