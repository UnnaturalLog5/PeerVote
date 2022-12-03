package impl

import (
	"errors"
	"time"

	"go.dedis.ch/cs438/types"
)

func (n *node) StartElection() error {
	// TODO
	// pass these as parameters

	// generate election id
	choices := []types.Choice{
		{
			// ChoiceID: xid.New().String(),
			ChoiceID: "a",
			Name:     "A Good Choice",
		},
		{
			// ChoiceID: xid.New().String(),
			ChoiceID: "b",
			Name:     "A Better Choice",
		},
	}
	expirationTime := time.Now().Add(time.Second * 30)

	random_neighbor, ok := n.routingTable.GetRandomNeighbor(n.myAddr)
	if !ok {
		return errors.New("no neighbor")
	}
	mixnetServers := []string{
		random_neighbor,
	}

	startElectionMessage := types.StartElectionMessage{
		// ElectionID:    xid.New().String(),
		ElectionID:    "1",
		Initiator:     n.myAddr,
		Choices:       choices,
		Expiration:    expirationTime,
		MixnetServers: mixnetServers,
	}

	err := n.sendStartElectionMessage(startElectionMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) GetElections() []types.Election {
	elections := n.electionStore.GetAll()

	return elections
}

func (n *node) Vote(electionID string, choice string) error {
	// broadcast as private message
	voteMessage := types.VoteMessage{
		ElectionID: electionID,
		Vote:       choice,
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
