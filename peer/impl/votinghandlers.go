package impl

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) HandleStartElectionMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling StartElection from %v", pkt.Header.Source)

	startElectionMessage := types.StartElectionMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &startElectionMessage)
	if err != nil {
		return err
	}

	election := types.Election{
		ElectionID:    startElectionMessage.ElectionID,
		Initiator:     startElectionMessage.Initiator,
		Choices:       startElectionMessage.Choices,
		Expiration:    startElectionMessage.Expiration,
		Description:   startElectionMessage.Description,
		MixnetServers: startElectionMessage.MixnetServers,
	}

	if n.electionStore.Exists(election.ElectionID) {
		return errors.New("election already exists")
	}

	n.electionStore.Set(election.ElectionID, election)

	// TODO
	// if i am the first mixnet server, set timer for expiration to start with mixing
	if election.MixnetServers[0] == n.myAddr {
		go func() {
			// wait until the set expiration date until tallying votes
			expireIn := election.Expiration.Sub(time.Now())
			<-time.After(expireIn)

			// TODO
			// mix and forward
			// n.MixAndForward()

			// for now just start tallying

		}()
	}
	return nil
}

func (n *node) HandleVoteMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling Vote from %v", pkt.Header.Source)
	voteMessage := types.VoteMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &voteMessage)
	if err != nil {
		return err
	}

	election := n.electionStore.Get(voteMessage.ElectionID)

	// only handle if we're the first mixnet server
	// actually, this should be sent in a private message so we don't need this
	// if election.MixnetServers[0] == n.myAddr {
	// 	return nil
	// }

	// accept if not expired
	if !time.Now().Before(election.Expiration) {
		return errors.New("this election expired - vote won't be accepted")
	}

	n.electionStore.StoreVote(election.ElectionID, voteMessage.Vote)

	return nil
}

func (n *node) HandleResultMessage(t types.Message, pkt transport.Packet) error {
	resultMessage := types.ResultMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &resultMessage)
	if err != nil {
		return err
	}

	// update election record
	// TODO
	// when updating winner, the mutex is unlocked
	// should be unproblematic in this step
	// but it _might_ cause some nasty bugs
	election := n.electionStore.Get(resultMessage.ElectionID)
	election.Winner = resultMessage.Winner
	n.electionStore.Set(election.ElectionID, election)

	return nil
}
