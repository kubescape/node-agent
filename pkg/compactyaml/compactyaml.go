package compactyaml

import (
	"bytes"
	"encoding/json"
	"sort"

	"gopkg.in/yaml.v3"
)

func Marshal(obj any) ([]byte, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	compact(&doc)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func compact(n *yaml.Node) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			compact(c)
		}
	case yaml.MappingNode:
		n.Style = 0
		sortKeys(n)
		for i := 0; i < len(n.Content); i += 2 {
			n.Content[i].Style = 0
			compact(n.Content[i+1])
		}
	case yaml.ScalarNode:
		n.Style = 0
	case yaml.SequenceNode:
		n.Style = 0
		if len(n.Content) == 0 {
			n.Style = yaml.FlowStyle
			return
		}
		for _, c := range n.Content {
			if c.Kind == yaml.MappingNode {
				flow(c)
			} else {
				compact(c)
			}
		}
	}
}

func flow(n *yaml.Node) {
	switch n.Kind {
	case yaml.ScalarNode:
		n.Style = 0
	case yaml.MappingNode, yaml.SequenceNode:
		n.Style = yaml.FlowStyle
		if n.Kind == yaml.MappingNode {
			sortKeys(n)
		}
		for _, c := range n.Content {
			flow(c)
		}
	}
}

func sortKeys(n *yaml.Node) {
	pairs := make([][2]*yaml.Node, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		pairs = append(pairs, [2]*yaml.Node{n.Content[i], n.Content[i+1]})
	}
	sort.SliceStable(pairs, func(a, b int) bool { return pairs[a][0].Value < pairs[b][0].Value })
	n.Content = n.Content[:0]
	for _, p := range pairs {
		n.Content = append(n.Content, p[0], p[1])
	}
}
