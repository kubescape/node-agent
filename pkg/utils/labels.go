package utils

import (
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func parseStringToMap(s string) map[string]string {
	result := make(map[string]string)

	// 1. Split the string by the comma delimiter to get key-value pairs
	pairs := strings.Split(s, ",")

	for _, pair := range pairs {
		// Trim any leading/trailing whitespace from the pair
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue // Skip empty pairs that could result from multiple commas
		}

		// 2. Split each pair by the equals sign delimiter.
		//    We use SplitN(pair, "=", 2) to ensure that only the first
		//    equals sign is treated as the delimiter, allowing values to
		//    contain equals signs (though not the case in the example).
		parts := strings.SplitN(pair, "=", 2)

		if len(parts) != 2 {
			// Handle malformed pairs (e.g., "key" or "key=value=extra")
			logger.L().Debug("Malformed key-value pair", helpers.String("pair", pair))
			continue
		}

		// Trim whitespace from key and value and add to the map
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		result[key] = value
	}

	return result
}
