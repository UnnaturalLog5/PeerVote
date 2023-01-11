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
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling StartElectionMessage from %v", pkt.Header.Source)

	startElectionMessage := types.StartElectionMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &startElectionMessage)
	if err != nil {
		return err
	}

	election := types.Election{
		Base: startElectionMessage.Base,
	}

	if n.electionStore.Exists(election.Base.ElectionID) {
		return errors.New("election already exists")
	}

	n.electionStore.Set(election.Base.ElectionID, election)

	// if i am the first mixnet server, set timer for expiration to start with mixing
	if election.Base.MixnetServers[0] == n.myAddr {
		go func() {
			// wait until the set expiration date until tallying votes
			expireIn := election.Base.Expiration.Sub(time.Now())
			<-time.After(expireIn)

			// mix and forward
			log.Info().Str("peerAddr", n.myAddr).Msgf("Election expired, starting mixing")
			// send to ourselves a MixMessage (hop 0) so we can bootstrap the mixing process
			n.Mix(election.Base.ElectionID, 0)
		}()
	}
	return nil
}

func (n *node) HandleVoteMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling VoteMessage from %v", pkt.Header.Source)
	voteMessage := types.VoteMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &voteMessage)
	if err != nil {
		return err
	}

	election := n.electionStore.Get(voteMessage.ElectionID)

	// accept if not expired
	if !time.Now().Before(election.Base.Expiration) {
		return errors.New("this election expired - vote won't be accepted")
	}

	n.electionStore.StoreVote(election.Base.ElectionID, voteMessage.ChoiceID)

	return nil
}

func (n *node) HandleMixMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling MixMessage from %v", pkt.Header.Source)
	mixMessage := types.MixMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &mixMessage)
	if err != nil {
		return err
	}

	election := n.electionStore.Get(mixMessage.ElectionID)
	election.Votes = mixMessage.Votes
	n.electionStore.Set(mixMessage.ElectionID, election)

	err = n.Mix(mixMessage.ElectionID, mixMessage.NextHop)
	if err != nil {
		return err
	}
	return nil
}

func (n *node) HandleResultMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling ResultsMessage from %v", pkt.Header.Source)
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
	election.Results = resultMessage.Results
	n.electionStore.Set(election.Base.ElectionID, election)

	return nil
}
