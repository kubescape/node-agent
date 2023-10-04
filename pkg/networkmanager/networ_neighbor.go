package networkmanager

type NetworkNeighbors struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

type Metadata struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"` // Assuming the labels are key-value pairs
}

type Spec struct {
	Labels  map[string]string `json:"labels"`
	Ingress []Ingress         `json:"ingress"`
	Egress  []Egress          `json:"egress"`
}

type Ingress struct {
	Type              string      `json:"type"`
	Identifier        string      `json:"identifier"`
	NamespaceSelector MatchLabels `json:"namespaceSelector"`
	PodSelector       MatchLabels `json:"podSelector"`
	Ports             []Port      `json:"ports"`
}

type Egress struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	IPAddress  string `json:"ipAddress"`
	DNS        string `json:"dns"`
	Ports      []Port `json:"ports"`
}

type MatchLabels struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

type Port struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}
