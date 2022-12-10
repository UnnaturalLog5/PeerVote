package types

import "time"

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

type StartElectionMessage struct {
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
