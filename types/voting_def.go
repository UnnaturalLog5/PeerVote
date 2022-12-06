package types

import "time"

type Election struct {
	ElectionID    string
	Initiator     string
	Title         string
	Description   string
	Choices       []Choice
	Expiration    time.Time
	MixnetServers []string
	Winner        string
	Votes         []string
	// Proofs
}

type Choice struct {
	ChoiceID string
	Name     string
}

type StartElectionMessage struct {
	ElectionID    string
	Initiator     string
	Choices       []Choice
	Expiration    time.Time
	Description   string
	MixnetServers []string
}

type VoteMessage struct {
	ElectionID string
	Vote       string
	// Proof
}

// type MixedVotesMessage struct {
// 	ElectionID string
// 	Votes      []string
// 	// Proofs
// }

type ResultMessage struct {
	ElectionID string
	Winner     string
	// Proof
}
