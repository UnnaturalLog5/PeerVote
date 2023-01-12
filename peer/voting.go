package peer

import (
	"time"

	"go.dedis.ch/cs438/types"
)

type Voting interface {
	AnnounceElection(title, description string, choices, mixnetServers []string, expirationTime time.Duration) (string, error)

	GetElections() []*types.Election

	Vote(electionID string, choiceID string) error

	// VerifyProof(...) ...
}
