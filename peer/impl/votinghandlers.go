package impl

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) HandleAnnounceElectionMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling AnnounceElectionMessage from %v", pkt.Header.Source)

	startElectionMessage := types.AnnounceElectionMessage{}
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

	//
	if contains(election.Base.MixnetServers, n.myAddr) {
		// if node is one of the mixnet servers, it needs to store the data about other mixnet servers
		election.Base.MixnetServerInfos = make([]types.MixnetServerInfo, len(election.Base.MixnetServers))
		n.electionStore.Set(election.Base.ElectionID, election)
		n.PedersenDkg(election.Base.ElectionID, election.Base.MixnetServers)
	} else {
		n.electionStore.Set(election.Base.ElectionID, election)
	}

	// TODO
	// if i am the first mixnet server, set timer for expiration to start with mixing
	if election.Base.MixnetServers[0] == n.myAddr {
		go func() {
			// wait until the set expiration date until tallying votes
			expireIn := election.Base.Expiration.Sub(time.Now())
			<-time.After(expireIn)

			// TODO
			// mix and forward
			// n.MixAndForward()

			// for now just start tallying

			log.Info().Str("peerAddr", n.myAddr).Msgf("Election expired, starting tallying")
			n.Tally(election.Base.ElectionID)
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
