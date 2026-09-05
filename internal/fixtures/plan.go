// Package fixtures plans explicitly declared fixture dependencies.
package fixtures

import (
	"fmt"
	"sort"
)

type Node struct {
	Name      string
	DependsOn []string
}

// Plan returns deterministic dependency order. It deliberately refuses to infer
// dependencies from database metadata or fixture values.
func Plan(nodes []Node) ([]Node, error) {
	byName := map[string]Node{}
	incoming := map[string]int{}
	children := map[string][]string{}
	for _, n := range nodes {
		if n.Name == "" {
			return nil, fmt.Errorf("fixture name is required")
		}
		if _, ok := byName[n.Name]; ok {
			return nil, fmt.Errorf("duplicate fixture %q", n.Name)
		}
		byName[n.Name] = n
		incoming[n.Name] = 0
	}
	for _, n := range nodes {
		for _, d := range n.DependsOn {
			if _, ok := byName[d]; !ok {
				return nil, fmt.Errorf("fixture %q depends on unknown %q", n.Name, d)
			}
			incoming[n.Name]++
			children[d] = append(children[d], n.Name)
		}
	}
	ready := []string{}
	for name, n := range incoming {
		if n == 0 {
			ready = append(ready, name)
		}
	}
	sort.Strings(ready)
	out := []Node{}
	for len(ready) > 0 {
		name := ready[0]
		ready = ready[1:]
		out = append(out, byName[name])
		for _, child := range children[name] {
			incoming[child]--
			if incoming[child] == 0 {
				ready = append(ready, child)
			}
		}
		sort.Strings(ready)
	}
	if len(out) != len(nodes) {
		return nil, fmt.Errorf("fixture dependencies contain a cycle")
	}
	return out, nil
}
