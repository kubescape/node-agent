package hostrules

import (
	_ "embed"
	"encoding/json"
)

var (
	writeFlags = []string{
		"O_WRONLY",
		"O_RDWR",
		"O_TRUNC",
		"O_CREAT",
		"O_APPEND"}

	allowedNamespaces = map[string]bool{
		"ci":          true, // CI/CD pipelines
		"jenkins":     true, // Jenkins workloads
		"gitlab":      true, // GitLab runners
		"build":       true, // Build environments
		"docker-mgmt": true, // Docker management tools
	}
)

//go:embed data/suspicious_tools.json
var suspiciousToolsJSON []byte

var suspiciousTools = func() map[string]toolInfo {
	var result struct {
		Tools []toolInfo `json:"tools"`
	}

	if err := json.Unmarshal(suspiciousToolsJSON, &result); err != nil {
		panic(err)
	}

	toolMap := make(map[string]toolInfo)
	for _, tool := range result.Tools {
		toolMap[tool.Name] = tool
	}

	return toolMap
}()
