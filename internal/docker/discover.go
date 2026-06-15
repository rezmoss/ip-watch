package docker

import (
	"context"
	"strings"
)

// Candidate: running ctr that looks like a webserver.
type Candidate struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	Engine string `json:"engine"` // guess, "" if unknown
}

// engineHints: image substring -> engine.
var engineHints = map[string]string{
	"nginx":   "nginx",
	"caddy":   "caddy",
	"httpd":   "apache",
	"apache":  "apache",
	"haproxy": "haproxy",
}

// Discover: running ctrs that look like webservers.
func Discover(ctx context.Context, socket string) ([]Candidate, error) {
	client := NewClient(socket)
	if err := client.Ping(ctx); err != nil {
		return nil, err
	}
	containers, err := client.List(ctx)
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, container := range containers {
		engine := guessEngine(container)
		if engine == "" && !exposesWebPort(container) {
			continue
		}
		candidates = append(candidates, Candidate{
			ID:     container.ID[:min(12, len(container.ID))],
			Name:   container.Name(),
			Image:  container.Image,
			Engine: engine,
		})
	}
	return candidates, nil
}

func guessEngine(container Container) string {
	image := strings.ToLower(container.Image)
	for hint, engine := range engineHints {
		if strings.Contains(image, hint) {
			return engine
		}
	}
	return ""
}

func exposesWebPort(container Container) bool {
	for _, port := range container.Ports {
		if port.PrivatePort == 80 || port.PrivatePort == 443 || port.PrivatePort == 8080 {
			return true
		}
	}
	return false
}
