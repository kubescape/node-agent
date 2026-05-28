package main

import (
	"context"
	"os"

	beUtils "github.com/kubescape/backend/pkg/utils"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	_ "modernc.org/sqlite"
)

func main() {
	ctx := context.Background()

	// Load ARMO credentials from /etc/credentials (same source as the main agent).
	// Fall back to env vars so the binary stays functional in non-ARMO deployments.
	accountID := os.Getenv("ACCOUNT_ID")
	accessKey := os.Getenv("ACCESS_KEY")
	if creds, err := beUtils.LoadCredentialsFromFile("/etc/credentials"); err == nil {
		if creds.Account != "" {
			accountID = creds.Account
		}
		if creds.AccessKey != "" {
			accessKey = creds.AccessKey
		}
	}

	// Run the reusable SBOM scanner server
	sbomscanner.RunServer(ctx, accountID, accessKey)
}
