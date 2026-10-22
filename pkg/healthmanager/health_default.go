//go:build !experimental_signing

package healthmanager

type policyHealth struct{}

func (h *HealthManager) registerPolicyHandler() {}
