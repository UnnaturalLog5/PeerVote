package impl

import (
	"errors"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/types"
)

func (n *node) StartElection(title, description string, choices, mixnetServers []string, electionDuration time.Duration) (string, error) {
	// generate election id
	electionChoices := []types.Choice{}
	for _, choice := range choices {
		electionChoices = append(electionChoices, types.Choice{
			ChoiceID: xid.New().String(),
			Name:     choice,
		})
	}

	expirationTime := time.Now().Add(electionDuration)

	electionID := xid.New().String()
	startElectionMessage := types.StartElectionMessage{
		Base: types.ElectionBase{
			ElectionID:    electionID,
			Initiator:     n.myAddr,
			Title:         title,
			Description:   description,
			Choices:       electionChoices,
			Expiration:    expirationTime,
			MixnetServers: mixnetServers,
		},
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
		ChoiceID:   choiceID,
	}

	election := n.electionStore.Get(electionID)

	if election.MyVote != "" {
		return errors.New("this peer has already voted")
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

func (n *node) Mix(electionID string, hop uint) error {
	election := n.electionStore.Get(electionID)
	votes := election.Votes

	// TODO
	// do the actual mixing
	// mixedVotes := peervotecrypto.Mix(votes)

	// for now
	mixedVotes := votes

	nextHop := hop + 1

	if nextHop >= uint(len(election.Base.MixnetServers)) {
		// done with mixing -> tally
		log.Info().Str("peerAddr", n.myAddr).Msgf("Last mixnet node reached: Start Tallying")
		n.Tally(electionID, mixedVotes)
		return nil
	}

	// otherwise continue forwarding to the next mixnet server

	mixMessage := types.MixMessage{
		ElectionID: electionID,
		Votes:      mixedVotes,
		NextHop:    nextHop,
	}

	// get address for next hop
	mixnetPeer := election.Base.MixnetServers[mixMessage.NextHop]

	recipients := make(map[string]struct{})
	recipients[mixnetPeer] = struct{}{}

	err := n.sendPrivateMessage(recipients, mixMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) Tally(electionID string, votes []string) {
	election := n.electionStore.Get(electionID)

	// we want 0 to show up as a count as well
	// inefficient, but doesn't matter
	results := map[string]uint{}
	for _, choice := range election.Base.Choices {
		count := uint(0)
		for _, vote := range votes {
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
