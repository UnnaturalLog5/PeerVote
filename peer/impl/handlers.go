package impl

import (
	"encoding/json"
	"math/rand"
	"regexp"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// --- Message Handlers ---

// is type of registry.Exec
func (n *node) HandleChatMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("received message: '%v'", string(pkt.Msg.Payload))
	return nil
}

// is type of registry.Exec
func (n *node) HandleRumorsMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling rumorsMessage from %v", pkt.Header.Source)

	// sendAck after processing rumors
	defer func() {
		err := n.sendAck(pkt)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msgf("could not acknowledge pkt %v", pkt.Header.PacketID)
		}
	}()

	rumorsMessage := types.RumorsMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &rumorsMessage)
	if err != nil {
		return err
	}

	// set forward to true if there is a rumor we expected
	forward := false
	for _, rumor := range rumorsMessage.Rumors {

		// is rumor expected?
		// Store only works if the rumor is expected, otherwise an error is passed
		err = n.rumorStore.Store(rumor)
		if err != nil {
			// rumor was unexpected -> skip processing
			log.Info().Str("peerAddr", n.myAddr).Msg("received unexpected rumor, skipping")
			continue
		}

		// update routing, but not if neighbor already
		n.routingTable.SetEntry(rumor.Origin, pkt.Header.RelayedBy)

		forward = true

		// process rumor locally
		rumorPkt := transport.Packet{
			Header: pkt.Header,
			Msg:    rumor.Msg,
		}

		err := n.conf.MessageRegistry.ProcessPacket(rumorPkt)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("could not process packet")
		}
	}

	if forward {
		randomNeighborAddr, ok := n.routingTable.GetRandomNeighbor(n.myAddr, pkt.Header.Source)
		if !ok {
			log.Warn().Str("peerAddr", n.myAddr).Msg("could not forward rumor, there is no more neighbor")
			return nil
		}

		log.Info().Str("peerAddr", n.myAddr).Msgf("forwarding rumor to %v", randomNeighborAddr)
		_, err = n.sendRumors(randomNeighborAddr, rumorsMessage.Rumors)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msgf("did not send missing rumors to %v", randomNeighborAddr)
		}
	}

	return nil
}

// is type of registry.Exec
func (n *node) HandleAckMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling ack from %v", pkt.Header.Source)

	// process rumor
	ackMessage := types.AckMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &ackMessage)
	if err != nil {
		return err
	}

	// if this ack was expected, clean up timer
	pktID := ackMessage.AckedPacketID
	ok := n.notfify.Notify(pktID)
	if ok {
		// stopped an active timer
		log.Info().Str("peerAddr", n.myAddr).Msgf("ack received - stopped waiting for ack for pkt %v", pktID)
	}

	err = n.processStatusMessage(pkt.Header.Source, ackMessage.Status)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) HandleEmptyMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling heartbeat message from %v", pkt.Header.Source)
	return nil
}

func (n *node) HandleDataReplyMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling data reply message message from %v", pkt.Header.Source)

	dataReplyMessage := types.DataReplyMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &dataReplyMessage)
	if err != nil {
		return err
	}

	requestID := dataReplyMessage.RequestID
	data := dataReplyMessage.Value

	ok := n.notfify.Notify(requestID, data)
	if !ok {
		log.Info().Str("peerAddr", n.myAddr).Msgf("error sending data reply to waiting goroutine")
	}

	return nil
}

func (n *node) HandleDataRequestMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling data request message from %v", pkt.Header.Source)

	dataRequestMessage := types.DataRequestMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &dataRequestMessage)
	if err != nil {
		return err
	}

	peer := pkt.Header.Source
	key := dataRequestMessage.Key
	requestID := dataRequestMessage.RequestID

	data := n.dataBlobStore.Get(key)

	// send data reply message
	err = n.sendDataReply(peer, requestID, key, data)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) HandleSearchReplyMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling search reply message from %v", pkt.Header.Source)
	seachReplyMessage := types.SearchReplyMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &seachReplyMessage)
	if err != nil {
		return err
	}

	responses := seachReplyMessage.Responses
	requestID := seachReplyMessage.RequestID

	n.notfify.Notify(requestID, responses)

	// update catalog
	for _, fileInfo := range responses {
		n.UpdateCatalog(
			fileInfo.Metahash,
			pkt.Header.Source,
		)

		for _, chunk := range fileInfo.Chunks {
			if chunk != nil {
				n.UpdateCatalog(
					string(chunk),
					pkt.Header.Source,
				)
			}
		}

		err = n.Tag(
			fileInfo.Name,
			fileInfo.Metahash,
		)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("tagging failed")
		}
	}

	return nil
}

func (n *node) HandleSearchRequestMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling search request message from %v", pkt.Header.Source)
	seachRequestMessage := types.SearchRequestMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &seachRequestMessage)
	if err != nil {
		return err
	}

	reg := regexp.MustCompile(seachRequestMessage.Pattern)
	requestID := seachRequestMessage.RequestID

	// check if already received
	_, requestKnown := n.knownRequests.Load(requestID)
	if requestKnown {
		return nil
	}

	// remember requestID
	n.knownRequests.Store(requestID, struct{}{})

	// get locally known files
	fileInfos := n.getFileInfos(*reg)

	// send search reply message
	searchReplyMessage := types.SearchReplyMessage{
		RequestID: requestID,
		Responses: fileInfos,
	}

	searchOrigin := seachRequestMessage.Origin
	sendTo := pkt.Header.Source
	err = n.sendSearchReplyMessage(searchOrigin, sendTo, searchReplyMessage)
	if err != nil {
		return err
	}

	// keep packet
	// just set origin and relayed by to this peer
	// distribute remaining seachRequestMessage.Budget
	// forward searchrequestmessage
	peers := n.routingTable.GetNeighborsList(n.myAddr, pkt.Header.Source)
	// we split the remaining budget
	peerBudgets := getPeerBudgets(peers, seachRequestMessage.Budget-1)
	for peer, budget := range peerBudgets {
		log.Info().Str("peerAddr", n.myAddr).Msgf("forwarding search request message from %v to %v", pkt.Header.Source, peer)
		err = n.forwardSearchRequest(searchOrigin, peer, budget, *reg, requestID)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msgf("couldn't forward search request from %v to %v", pkt.Header.Source, peer)
		}
	}

	return nil
}

// is type of registry.Exec
func (n *node) HandlePrivateMessage(t types.Message, pkt transport.Packet) error {
	privateMessage := types.PrivateMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &privateMessage)
	if err != nil {
		return err
	}

	_, ok := privateMessage.Recipients[n.myAddr]
	if !ok {
		return nil
	}

	localPkt := transport.Packet{
		Header: pkt.Header,
		Msg:    privateMessage.Msg,
	}

	log.Info().Str("peerAddr", n.myAddr).Msgf("handling privateMessage from %v", pkt.Header.Source)
	err = n.conf.MessageRegistry.ProcessPacket(localPkt)
	if err != nil {
		return err
	}

	return nil
}

// is type of registry.Exec
func (n *node) HandleStatusMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling statusMessage from %v", pkt.Header.Source)

	// process rumor
	statusMessage := types.StatusMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &statusMessage)
	if err != nil {
		return err
	}

	err = n.processStatusMessage(pkt.Header.Source, statusMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) processStatusMessage(origin string, remoteStatus types.StatusMessage) error {
	localStatus := n.rumorStore.MakeStatusMessage()

	sendStatus := false
	continueMongering := true
	rumorsToSend := make([]types.Rumor, 0)

	peers := make(map[string]struct{}, 0)

	for peer := range localStatus {
		peers[peer] = struct{}{}
	}
	for peer := range remoteStatus {
		peers[peer] = struct{}{}
	}

	// figure
	for peer := range peers {
		remoteSequence := remoteStatus[peer]
		localSequence := localStatus[peer]

		switch {
		case localSequence > remoteSequence:
			continueMongering = false

			rumors := n.rumorStore.GetRumors(peer, remoteSequence)

			rumorsToSend = append(rumorsToSend, rumors...)

		case localSequence < remoteSequence:
			continueMongering = false
			// this peer has rumors remote peer doesn't have
			// send statusMesage
			sendStatus = true
		}

	}

	if sendStatus {
		// send our status back to peer
		err := n.sendStatusMessage(origin)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("did not send status message")
		}

		log.Info().Str("peerAddr", n.myAddr).Msgf("sent statusMessage to %v to solicitate rumors", origin)
	}

	if len(rumorsToSend) > 0 {
		// send rumors to peer
		_, err := n.sendRumors(origin, rumorsToSend)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("did not send missing rumors")
		}
		log.Info().Str("peerAddr", n.myAddr).Msgf("sent %v missing rumors to %v", len(rumorsToSend), origin)
	}

	if continueMongering {
		// send status message to random neighbor
		if rand.Float64() < n.conf.ContinueMongering {
			log.Info().Str("peerAddr", n.myAddr).Msgf("continue mongering, send status message to random neighbor")
			err := n.sendStatusMessageToRandomNeighbor(origin)
			if err != nil {
				log.Info().Str("peerAddr", n.myAddr).Msgf("could not continue mongering, there is no more neighbor")
			}
		}
	}

	return nil
}

func (n *node) HandlePaxosPrepareMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling Paxos Prepare from %v", pkt.Header.Source)

	paxosPrepareMessage := types.PaxosPrepareMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &paxosPrepareMessage)
	if err != nil {
		return err
	}

	paxosPromiseMessage, ok := n.multiPaxos.HandlePrepare(paxosPrepareMessage)
	if !ok {
		// ignore
		return nil
	}

	dest := paxosPrepareMessage.Source
	err = n.sendPaxosPromiseMessage(dest, paxosPromiseMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) HandlePaxosPromiseMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling Paxos Promise from %v", pkt.Header.Source)

	paxosPromiseMessage := types.PaxosPromiseMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &paxosPromiseMessage)
	if err != nil {
		return err
	}

	n.multiPaxos.HandlePromise(paxosPromiseMessage)

	return nil
}

func (n *node) HandlePaxosProposeMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling Paxos Propose from %v", pkt.Header.Source)

	paxosProposeMessage := types.PaxosProposeMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &paxosProposeMessage)
	if err != nil {
		return err
	}

	paxosAcceptMessage, ok := n.multiPaxos.HandlePropose(paxosProposeMessage)
	if !ok {
		// ignore
		return nil
	}

	err = n.sendPaxosAcceptMessage(paxosAcceptMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) HandlePaxosAcceptMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling Paxos Accept from %v", pkt.Header.Source)

	paxosAcceptMessage := types.PaxosAcceptMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &paxosAcceptMessage)
	if err != nil {
		return err
	}

	n.multiPaxos.HandleAccept(paxosAcceptMessage)

	return nil
}

func (n *node) HandleTLCMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling TLC from %v", pkt.Header.Source)

	TLCMessage := types.TLCMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &TLCMessage)
	if err != nil {
		return err
	}

	return nil
}
