package impl

import (
	"encoding/json"
	"errors"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func marshalMessage(msg types.Message) (transport.Message, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return transport.Message{}, err
	}

	transportMessage := transport.Message{
		Type:    msg.Name(),
		Payload: data,
	}

	return transportMessage, nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	// make header
	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		dest,
		0,
	)

	// assemble packet
	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	// send off packet
	err := n.route(dest, pkt)
	if err != nil {
		return err
	}

	return nil
}

// Broadcast implements peer.Messaging
func (n *node) Broadcast(msg transport.Message) error {
	mySequenceNumber := n.rumorStore.GetSequence(n.myAddr) + 1

	// create rumor
	rumor := types.Rumor{
		Origin:   n.myAddr,
		Sequence: mySequenceNumber,
		Msg:      &msg,
	}

	// store own rumor
	err := n.rumorStore.Store(rumor)
	if err != nil {
		return err
	}

	// process locally
	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		"",
		0,
	)

	localPkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	err = n.conf.MessageRegistry.ProcessPacket(localPkt)
	if err != nil {
		return err
	}

	rumors := []types.Rumor{rumor}

	randomNeighborAddr, err := n.routingTable.GetRandomNeighbor(n.myAddr)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msg("could not send broadcast")
	}

	pkt, err := n.sendRumors(randomNeighborAddr, rumors)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msg("could not send broadcast")
		return nil
	}

	if n.conf.AckTimeout > 0 {
		// wait for acknowledgement
		go n.waitForAck(pkt)
	}

	return nil
}

// forward packet
func (n *node) forward(dest string, pkt transport.Packet) error {
	relayPkt := pkt.Copy()

	// update packet header with this peer's address
	relayPkt.Header.RelayedBy = n.myAddr

	// send off packet
	err := n.route(dest, relayPkt)
	if err != nil {
		return err
	}

	return nil
}

// routes a transport.Packet to its destination
func (n *node) route(dest string, pkt transport.Packet) error {
	// get address to which to relay to
	relayAddr := n.routingTable.GetEntry(dest)
	if relayAddr == "" {
		return errors.New("node with address %v cannot be found in routing table")
	}

	// send to destination
	err := n.conf.Socket.Send(relayAddr, pkt, 0)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) sendAck(pkt transport.Packet) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("acknowledging receipt of pkt from %v", pkt.Header.Source)

	dest := pkt.Header.Source

	status := types.StatusMessage(n.rumorStore.StatusMessage())

	ackMessage := types.AckMessage{
		AckedPacketID: pkt.Header.PacketID,
		Status:        status,
	}

	msg, err := marshalMessage(ackMessage)
	if err != nil {
		return err
	}

	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		dest,
		0,
	)

	ackPkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	err = n.conf.Socket.Send(dest, ackPkt, 0)
	if err != nil {
		return err
	}

	return nil
}

// sends status message to a dest, or if set to ""
// send to random neighbor except ourselves
// and the forbiddenPeers passed in
func (n *node) sendStatusMessage(dest string, forbiddenPeers ...string) error {
	statusMessage := n.rumorStore.StatusMessage()

	msg, err := marshalMessage(statusMessage)
	if err != nil {
		return err
	}

	if dest == "" {
		// send to random neighbor
		// except ourselves and other forbiddenPeers
		forbiddenPeers = append(forbiddenPeers, n.myAddr)
		dest, err = n.routingTable.GetRandomNeighbor(forbiddenPeers...)
		if err != nil {
			return err
		}
	}

	// make header
	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		dest,
		0,
	)

	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	// send to destination
	err = n.conf.Socket.Send(dest, pkt, 0)
	if err != nil {
		return err
	}

	return nil
}

// sends rumors message to destination
// returns the packet ID used so that the initiator may wait for an ack
func (n *node) sendRumors(dest string, rumors []types.Rumor) (transport.Packet, error) {
	rumorsMessage := types.RumorsMessage{Rumors: rumors}

	msg, err := marshalMessage(rumorsMessage)
	if err != nil {
		return transport.Packet{}, err
	}

	// make header
	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		dest,
		0,
	)

	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	err = n.conf.Socket.Send(dest, pkt, 0)
	if err != nil {
		return transport.Packet{}, err
	}

	return pkt, nil
}

func (n *node) sendHeartbeat() error {
	emptyMessage := types.EmptyMessage{}.NewEmpty()

	msg, err := marshalMessage(emptyMessage)
	if err != nil {
		return err
	}

	err = n.Broadcast(msg)
	if err != nil {
		return err
	}
	return nil
}

func (n *node) waitForAck(pkt transport.Packet) {
	pktID := pkt.Header.PacketID

	// wait for ack
	n.ackTimers.Set(pktID, n.conf.AckTimeout)

	// wait for timer
	n.ackTimers.Wait(pktID)

	// send message to another neighbor

	// get another neighbor
	randomNeighborAddr, err := n.routingTable.GetRandomNeighbor(n.myAddr, pkt.Header.Destination)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msg("timer expired - did not forward rumor")
		return
	}

	log.Info().Str("peerAddr", n.myAddr).
		Msgf("timer expired - stopped waiting for ack for pkt %v, resending to %v instead", pktID, randomNeighborAddr)

	newPkt := pkt.Copy()

	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		randomNeighborAddr,
		0,
	)

	newPkt.Header = &header

	err = n.route(randomNeighborAddr, newPkt)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr)
	}
}
