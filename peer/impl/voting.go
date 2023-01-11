package impl

import (
	"errors"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/types"
)

func (n *node) AnnounceElection(title, description string, choices, mixnetServers []string, electionDuration time.Duration) (string, error) {
	// generate election id
	electionChoices := []types.Choice{}
	for _, choice := range choices {
		electionChoices = append(electionChoices, types.Choice{
			ChoiceID: xid.New().String(),
			Name:     choice,
		})
	}

	electionID := xid.New().String()
	mixnetServersPoints := make([]int, len(mixnetServers))
	initiators := make(map[string]struct{})

	announceElectionMessage := types.AnnounceElectionMessage{
		Base: types.ElectionBase{
			ElectionID:  electionID,
			Announcer:   n.myAddr,
			Title:       title,
			Description: description,
			Choices:     electionChoices,

			Duration: electionDuration,

			// initiated later (see HandleInitiateElectionMessage)
			// Expiration:    expirationTime,
			MixnetServers: mixnetServers,

			// initiated only if needed (see HandleAnnounceElectionMessage)
			// MixnetServerInfos:   make(make([]types.MixnetServerInfo, len(mixnetServers)),

			// Incremented when mixnet server is among qualified nodes in types.ElectionReadyMessage
			MixnetServersPoints: mixnetServersPoints,

			ElectionReadyCnt: 0,
			Initiators:       initiators,
		},
	}

	err := n.sendAnnounceElectionMessage(announceElectionMessage)
	if err != nil {
		return "", err
	}

	return electionID, nil
}

func (n *node) GetElections() []types.Election {
	elections := n.electionStore.GetAll()

	return elections
}

func (n *node) Vote(electionID string, choiceID string) error {
	// broadcast as private message
	voteMessage := types.VoteMessage{
		ElectionID: electionID,
		ChoiceID:   choiceID,
	}

	election := n.electionStore.Get(electionID)

	if election.MyVote != "" {
		return errors.New("this peer has already voted")
	}

	if !n.IsElectionStarted(election) {
		// todo display some kind of a message on frontend
		return errors.New("election hasn't started yet")
	}

	// TODO
	// rethink this mechanism, this might cause bugs when the vote is stored here
	// but sendVoteMessage fails without at least locally processing the rumor
	election.MyVote = voteMessage.ChoiceID
	n.electionStore.Set(voteMessage.ElectionID, election)

	mixnetServer := election.Base.MixnetServers[0]
	err := n.sendVoteMessage(mixnetServer, voteMessage)
	if err != nil {
		return err
	}

	return nil
}

// func (n *node) MixAndForward(electionID string, encryptedVotes []string) error {
// 	// mix
// 	// generate proofs

// 	election := n.electionStore.Get(electionID)

// 	myIndex := 0
// 	// get next minxet server
// 	for i, mixnetServer := range election.MixnetServers {
// 		if mixnetServer == n.myAddr {
// 			myIndex = i
// 		}
// 	}

// 	if myIndex < len(election.MixnetServers)-1 {
// 		// send mixed votes to next mixnet
// 		nextHop := election.MixnetServers[myIndex+1]

// 	} else {
// 		// I'm the last mixnet server
// 		// tally
// 	}

// 	return nil
// }

func (n *node) Tally(electionID string) {
	election := n.electionStore.Get(electionID)

	// we want 0 to show up as a count as well
	// inefficient, but doesn't matter
	results := map[string]uint{}
	for _, choice := range election.Base.Choices {
		count := uint(0)
		for _, vote := range election.Votes {
			if vote == choice.ChoiceID {
				count++
			}
		}

		results[choice.ChoiceID] = count
	}

	resultMessage := types.ResultMessage{
		ElectionID: electionID,
		Results:    results,
	}

	err := n.sendResultsMessage(resultMessage)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msgf("error broadcasting election results")
	}
}

func GetWinner(results map[string]uint) string {
	highestCount := uint(0)
	winner := ""

	for choice, count := range results {
		if count > highestCount {
			winner = choice
			highestCount = count
		}
	}

	return winner
}
