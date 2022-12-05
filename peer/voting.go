package peer

import (
	"time"

	"go.dedis.ch/cs438/types"
)

type Voting interface {
	StartElection(choices []string, expirationTime time.Time) (string, error)

	GetElections() []types.Election

	Vote(electionID string, choiceID string) error

	// VerifyProof(...) ...
}
