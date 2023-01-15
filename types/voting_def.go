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

	VotesPermutation []uint32
}

type Election struct {
	Base   ElectionBase
	MyVote int
	// choiceID -> count
	Results map[string]uint
	Votes   []ElGamalCipherText
}

type ElGamalCipherText struct {
	Ct1 Point
	Ct2 Point
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

// GetPublicKey returns the election public key from one of the qualified mixnet servers
func (election *Election) GetPublicKey() Point {
	return election.Base.Initiators[election.GetFirstQualifiedInitiator()]
}

// GetNextMixHop returns the ID of the next mixnet node for mixing
func (election *Election) GetNextMixHop(hop int) int {
	for i := hop + 1; i < len(election.Base.MixnetServersPoints); i++ {
		if election.Base.MixnetServersPoints[i] >= election.Base.Threshold {
			return i
		}
	}
	return -1
}

type Choice struct {
	ChoiceID int
	Name     string
}

type AnnounceElectionMessage struct {
	Base ElectionBase
}

type VoteMessage struct {
	ElectionID       string
	EncryptedVote    ElGamalCipherText
	CorrectVoteProof Proof
	CorectEncProof   Proof
}

type MixMessage struct {
	ElectionID string
	Votes      []ElGamalCipherText
	NextHop    int

	// Proofs
	ShuffleProofs      []ShuffleProof
	ReEncryptionProofs []Proof
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
