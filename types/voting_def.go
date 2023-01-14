package types

import (
	"math/big"
	"time"
)

// --- Election Types ---

type ElectionBase struct {
	ElectionID  string
	Announcer   string
	Title       string
	Description string
	Choices     []Choice

	Duration            time.Duration
	Expiration          time.Time
	MixnetServers       []string
	MixnetServerInfos   []*MixnetServerInfo
	MixnetServersPoints []int // Incremented when mixnet server is among qualified nodes in types.ElectionReadyMessage
	Threshold           int
	ElectionReadyCnt    int
	Initiators          map[string]Point
}

type Election struct {
	Base   ElectionBase
	MyVote string
	// choiceID -> count
	Results map[string]uint
	Votes   []string
}

// GetMyMixnetServerID returns the ID of the node within mixnet servers
func (election *Election) GetMyMixnetServerID(nodeAddr string) int {
	for i, addr := range election.Base.MixnetServers {
		if addr == nodeAddr {
			return i
		}
	}
	return -1
}

// IsElectionStarted checks if the election started (that is, one of the trusted mixnet
// servers initiated the election and the peer is allowed to cast a vote)
func (election *Election) IsElectionStarted() bool {
	if election.Base.ElectionReadyCnt != len(election.Base.MixnetServers) {
		return false
	}
	initiator := election.GetFirstQualifiedInitiator()
	println("initiator" + initiator)
	_, exists := election.Base.Initiators[initiator]
	return exists
}

// GetFirstQualifiedInitiator returns the ID of the mixnet server which is responsible for
// initiating the election
func (election *Election) GetFirstQualifiedInitiator() string {
	for i := 0; i < len(election.Base.MixnetServersPoints); i++ {
		if election.Base.MixnetServersPoints[i] >= election.Base.Threshold {
			return election.Base.MixnetServers[i]
		}
	}
	return ""
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

// Mixnet qualification status
const (
	NOT_DECIDED_YET = iota
	QUALIFIED
	DISQUALIFIED
)

// MixnetServerInfo contains the data about mixnet server which plays the role
// in Pedersen DKG protocol
type MixnetServerInfo struct {
	ReceivedShare   big.Int
	X               []Point
	VerifiedCnt     int
	ComplainedCnt   int
	QualifiedStatus int
}
