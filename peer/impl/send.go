package impl

import (
	"encoding/json"
	"errors"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// TODO move somewhere sensible
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
	mySequenceNumber := n.sequenceStore.Increment(n.myAddr)

	// create rumor
	rumor := types.Rumor{
		Origin:   n.myAddr,
		Sequence: mySequenceNumber,
		Msg:      &msg,
	}

	rumors := []types.Rumor{rumor}

	randomNeighborAddr, err := n.routingTable.GetRandomNeighbor(n.myAddr)
	if err != nil {
		// TODO think about error handling
		return nil
	}

	// TODO send Rumors
	err = n.sendRumors(randomNeighborAddr, rumors)
	if err != nil {
		// TODO think about error handling
		return nil
	}

	// process locally

	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		randomNeighborAddr,
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

	// TODO await ack

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

	// TODO send to relayedby or send to source?
	dest := pkt.Header.Source

	status := types.StatusMessage(n.sequenceStore.GetStatus())

	// TODO combine with code in n.Broadcast to smth like "makeTransportPkt(header, ...)"
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
	statusMessage := n.sequenceStore.GetStatus()

	msg, err := marshalMessage(statusMessage)
	if err != nil {
		return err
	}

	if dest == "" {
		// send to random neighbor
		// except ourselves and other forbiddenPeers
		forbiddenPeers = append(forbiddenPeers, n.myAddr)
		randomNeighborAddr, err := n.routingTable.GetRandomNeighbor(forbiddenPeers...)
		if err != nil {
			return err
		}

		dest = randomNeighborAddr
	}

	// TODO what if there is no other neighbor?

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

	err = n.route(dest, pkt)
	if err != nil {
		return err
	}

	return nil
}

// sends rumors message to destination
func (n *node) sendRumors(dest string, rumors []types.Rumor) error {
	rumorsMessage := types.RumorsMessage{Rumors: rumors}

	msg, err := marshalMessage(rumorsMessage)
	if err != nil {
		return err
	}

	// send to random neighbor

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

	err = n.route(dest, pkt)
	if err != nil {
		return err
	}

	return nil
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
