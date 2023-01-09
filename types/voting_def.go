package types

import (
	"math/big"
	"time"
)

type ElectionBase struct {
	ElectionID        string
	Initiator         string
	Title             string
	Description       string
	Choices           []Choice
	Expiration        time.Time
	MixnetServers     []string
	MixnetServerInfos []MixnetServerInfo
}

type Election struct {
	Base   ElectionBase
	MyVote string
	// choiceID -> count
	Results map[string]uint
	Votes   []string
}

type Choice struct {
	ChoiceID string
	Name     string
}

type AnnounceElectionMessage struct {
	Base ElectionBase
}

type VoteMessage struct {
	ElectionID string
	ChoiceID   string
	// Proof
}

// type MixedVotesMessage struct {
// 	ElectionID string
// 	Votes      []string
// 	// Proofs
// }

type ResultMessage struct {
	ElectionID string
	Results    map[string]uint
	// Proof
}

// MixnetServerInfo contains the data about mixnet server which plays the role
// in Pedersen DKG protocol
type MixnetServerInfo struct {
	ReceivedShare big.Int
	X             []big.Int
	VerifiedCnt   int
	ComplainedCnt int
}
