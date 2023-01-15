package impl

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) HandleAnnounceElectionMessage(t types.Message, pkt transport.Packet) error {
	n.dkgMutex.Lock()

	log.Info().Str("peerAddr", n.myAddr).Msgf("handling AnnounceElectionMessage from %v", pkt.Header.Source)

	announceElectionMessage := types.AnnounceElectionMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &announceElectionMessage)
	if err != nil {
		return err
	}

	voteWG := sync.WaitGroup{}
	voteWG.Add(1)
	election := types.Election{
		Base:   announceElectionMessage.Base,
		VoteWG: voteWG,
	}

	if n.electionStore.Exists(election.Base.ElectionID) {
		return errors.New("election already exists")
	}

	n.electionStore.Set(election.Base.ElectionID, &election)

	n.notfify.Notify(election.Base.ElectionID)

	n.dkgMutex.Unlock()

	if contains(election.Base.MixnetServers, n.myAddr) {
		// if node is one of the mixnet servers, it needs to store the data about other mixnet servers
		election.Base.MixnetServerInfos = make([]*types.MixnetServerInfo, len(election.Base.MixnetServers))
		n.PedersenDkg(&election)
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
	election := n.electionStore.Get(resultMessage.ElectionID)

	n.dkgMutex.Lock()
	election.Results = resultMessage.Results
	n.dkgMutex.Unlock()
	return nil
}
