package exporters

// HTTPKeyValues represents a key-value pair for HTTP headers or query parameters
type HTTPKeyValues struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
