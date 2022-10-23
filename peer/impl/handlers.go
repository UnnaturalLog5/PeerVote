package impl

import (
	"encoding/json"
	"errors"
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
	defer n.sendAck(pkt)

	// process rumor
	rumorsMessage := types.RumorsMessage{}
	// TODO capsule unmarshaling msgs
	err := json.Unmarshal(pkt.Msg.Payload, &rumorsMessage)
	if err != nil {
		// TODO
		return err
	}

	// set forward to true if there is a rumor we expect
	forward := false
	for _, rumor := range rumorsMessage.Rumors {
		currentSeq := n.sequenceStore.Get(rumor.Origin)

		// update routing, but not if neighbor already
		n.routingTable.SetEntry(rumor.Origin, pkt.Header.RelayedBy)

		// is rumor expected?
		// the first expected rumor breaks
		if rumor.Sequence == currentSeq+1 {
			forward = true

			n.sequenceStore.Increment(rumor.Origin)

			// store this rumor
			n.rumorStore.Store(rumor.Origin, rumor)

			// process rumor
			rumorPkt := transport.Packet{
				Header: pkt.Header,
				Msg:    rumor.Msg,
			}

			err := n.conf.MessageRegistry.ProcessPacket(rumorPkt)
			// TODO handle err
			if err != nil {
				// TODO
				return err
			}
		}
	}

	if forward {
		randomNeighborAddr, err := n.routingTable.GetRandomNeighbor(n.myAddr, pkt.Header.Source)

		if err != nil {
			log.Warn().Str("peerAddr", n.myAddr).Msg("could not forward rumor, there is no more neighbor")
		} else {
			err = n.sendRumors(randomNeighborAddr, rumorsMessage.Rumors)
			if err != nil {
				// TODO handle err
				return err
			}
		}

	}

	return nil
}

// is type of registry.Exec
func (n *node) HandleAckMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling ack from %v", pkt.Header.Source)
	// handle status
	return nil
}

func (n *node) HandleEmptyMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling heartbeat message from %v", pkt.Header.Source)
	// handle status
	return nil
}

// is type of registry.Exec
func (n *node) HandlePrivateMessage(t types.Message, pkt transport.Packet) error {
	privateMessage := types.PrivateMessage{}
	err := json.Unmarshal(pkt.Msg.Payload, &privateMessage)
	if err != nil {
		// TODO
		// return err
	}

	_, ok := privateMessage.Recipients[n.myAddr]
	if !ok {
		return errors.New("received private message meant for other peers")
	}

	err = n.conf.MessageRegistry.ProcessPacket(pkt)
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
		// TODO
		// return err
	}

	localStatus := n.sequenceStore.GetStatus()

	sendStatus := false
	continueMongering := true
	rumorsToSend := make([]types.Rumor, 0)

	// figure
	for peer, localSequence := range localStatus {
		remoteSequence := statusMessage[peer]

		switch {
		case localSequence == remoteSequence:
			// same view
			// do nothing for specific instances
			continue

		case localSequence > remoteSequence:
			continueMongering = false
			// send over missing
			// where do i get them???

			rumors := n.rumorStore.Get(peer, remoteSequence+1)

			rumorsToSend = append(rumorsToSend, rumors...)

		case localSequence < remoteSequence:
			continueMongering = false
			// this peer has rumors remote peer doesn't have
			// send statusMesage
			sendStatus = true
		}

	}

	// TODO debug scope issue of sendstatus, continueMongering, toSend

	if sendStatus {
		// send our status back to peer
		n.sendStatusMessage(pkt.Header.Source)
	}

	if len(rumorsToSend) != 0 {
		// send rumors to peer
		err = n.sendRumors(pkt.Header.Source, rumorsToSend)
		if err != nil {
			// TODO handle error
		}
	}

	if continueMongering {
		// send status message to random neighbor

		// TODO only send based on probability
		if rand.Float64() < n.conf.ContinueMongering {
			err := n.sendStatusMessage("", pkt.Header.Source)
			if err != nil {
				// TODO handle error
			}
		}
	}

	return nil
}
