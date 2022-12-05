package impl

import (
	"errors"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/types"
)

func (n *node) StartElection(choices []string, expirationTime time.Time) (string, error) {
	// generate election id
	electionChoices := []types.Choice{}
	for _, choice := range choices {
		electionChoices = append(electionChoices, types.Choice{
			ChoiceID: xid.New().String(),
			Name:     choice,
		})
	}

	// TODO
	// for now just set random neighbors as mixnet servers
	random_neighbor, ok := n.routingTable.GetRandomNeighbor()
	if !ok {
		return "", errors.New("no neighbor")
	}
	mixnetServers := []string{
		random_neighbor,
	}

	electionID := xid.New().String()
	startElectionMessage := types.StartElectionMessage{
		ElectionID:    electionID,
		Initiator:     n.myAddr,
		Choices:       electionChoices,
		Expiration:    expirationTime,
		MixnetServers: mixnetServers,
	}

	err := n.sendStartElectionMessage(startElectionMessage)
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
		Vote:       choiceID,
	}

	election := n.electionStore.Get(electionID)
	mixnetServer := election.MixnetServers[0]

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

func (n *node) Tally(electionID string, votes []string) error {
	results := map[string]int{}
	for _, vote := range votes {
		results[vote]++
	}

	highestCount := 0
	winner := ""
	for choice, count := range results {
		if count > highestCount {
			winner = choice
		}
	}

	resultMessage := types.ResultMessage{
		ElectionID: electionID,
		Winner:     winner,
	}

	err := n.sendResultsMessage(resultMessage)
	if err != nil {
		return err
	}

	return nil
}
