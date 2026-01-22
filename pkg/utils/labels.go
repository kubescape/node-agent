package utils

import (
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func parseStringToMap(s string) map[string]string {
	pairs := strings.Split(s, ",")
	result := make(map[string]string, len(pairs)/2)

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			logger.L().Debug("Malformed key-value pair", helpers.String("pair", pair))
			continue
		}

		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	return result
}
