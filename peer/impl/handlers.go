package impl

import (
	"encoding/json"
	"math/rand"

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

	// process rumor
	rumorsMessage := types.RumorsMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &rumorsMessage)
	if err != nil {
		return err
	}

	// set forward to true if there is a rumor we expected
	forward := false
	for _, rumor := range rumorsMessage.Rumors {
		// update routing, but not if neighbor already
		n.routingTable.SetEntry(rumor.Origin, pkt.Header.RelayedBy)

		// is rumor expected?
		// Store only works if the rumor is expected, otherwise an error is passed
		err = n.rumorStore.Store(rumor)
		if err != nil {
			// rumor was unexpected -> skip processing
			log.Info().Str("peerAddr", n.myAddr).Msg("received unexpected rumor, skipping")
			continue
		}

		forward = true

		// process rumor
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
		randomNeighborAddr, err := n.routingTable.GetRandomNeighbor(n.myAddr, pkt.Header.Source)
		if err != nil {
			log.Warn().Str("peerAddr", n.myAddr).Msg("could not forward rumor, there is no more neighbor")
		}

		log.Info().Str("peerAddr", n.myAddr).Msgf("forwarding rumor to %v", randomNeighborAddr)
		_, err = n.sendRumors(randomNeighborAddr, rumorsMessage.Rumors)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("did not send missing rumors")
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
	ok := n.timers.Stop(pktID, nil)
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

	log.Info().Str("peerAddr", n.myAddr).Msgf("about to stop timer")
	ok := n.timers.Stop(requestID, data)
	log.Info().Str("peerAddr", n.myAddr).Msgf("stopped timer")
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
	n.sendDataReply(peer, requestID, key, data)

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
	localStatus := n.rumorStore.StatusMessage()

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

	if len(rumorsToSend) != 0 {
		// send rumors to peer
		_, err := n.sendRumors(origin, rumorsToSend)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("did not send missing rumors")
		}
		log.Info().Str("peerAddr", n.myAddr).Msgf("sent missing rumors %v to %v", origin, rumorsToSend)
	}

	if continueMongering {
		// send status message to random neighbor
		if rand.Float64() < n.conf.ContinueMongering {
			err := n.sendStatusMessage("", origin)
			if err != nil {
				log.Info().Str("peerAddr", n.myAddr).Msgf("could not continue mongering, there is no more neighbor")
			}
		}
	}

	return nil
}
