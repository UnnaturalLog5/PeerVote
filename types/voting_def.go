package types

import "time"

// --- Election Types ---

type ElectionBase struct {
	ElectionID    string
	Initiator     string
	Title         string
	Description   string
	Choices       []Choice
	Expiration    time.Time
	MixnetServers []string
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

// --- Messages ---

type StartElectionMessage struct {
	Base ElectionBase
}

type VoteMessage struct {
	ElectionID string
	ChoiceID   string
	// Proof
}

type MixMessage struct {
	ElectionID string
	Votes      []string
	NextHop    uint
	// Proofs
}

type ResultMessage struct {
	ElectionID string
	Results    map[string]uint
	// Proof
}
