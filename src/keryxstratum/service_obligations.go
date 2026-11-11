package keryxstratum

import (
	"sort"

	w "github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
)

func (s *serviceRelay) nodeObligationsLocked(requests []string) (*w.GetAwaitedOpeningsResponseMessage, error) {
	responses := make([]string, 0, len(s.state.Tasks))
	for _, task := range s.state.Tasks {
		if task.ResponseID != "" {
			responses = append(responses, task.ResponseID)
		}
	}
	sort.Strings(responses)
	return s.rpc.GetAwaitedOpenings(s.state.Escrow, requests, responses)
}
