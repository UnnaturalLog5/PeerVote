package impl

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/rs/xid"
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

	randomNeighborAddr, ok := n.routingTable.GetRandomNeighbor(n.myAddr)
	if !ok {
		log.Err(err).Str("peerAddr", n.myAddr).Msg("could not send broadcast")
		// return err
		return nil
	}

	pkt, err := n.sendRumors(randomNeighborAddr, rumors)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msg("could not send broadcast")
		// return err
	}

	if n.conf.AckTimeout > 0 {
		// wait for acknowledgement
		go n.waitForAckOrResend(pkt)
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

	status := n.rumorStore.MakeStatusMessage()

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

func (n *node) sendStatusMessageToRandomNeighbor(forbiddenPeers ...string) error {
	forbiddenPeers = append(forbiddenPeers, n.myAddr)
	dest, ok := n.routingTable.GetRandomNeighbor(forbiddenPeers...)
	if !ok {
		return errors.New("no neighbor")
	}

	err := n.sendStatusMessage(dest)
	if err != nil {
		return err
	}

	return nil
}

// sends status message to a dest, or if set to ""
// send to random neighbor except ourselves
// and the forbiddenPeers passed in
func (n *node) sendStatusMessage(dest string) error {
	statusMessage := n.rumorStore.MakeStatusMessage()

	msg, err := marshalMessage(statusMessage)
	if err != nil {
		return err
	}

	err = n.unicastDirect(dest, msg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) unicastDirect(dest string, msg transport.Message) error {
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
	err := n.conf.Socket.Send(dest, pkt, 0)
	if err != nil {
		return err
	}

	return nil
}

// sends rumors message to destination
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
	log.Info().Str("peerAddr", n.myAddr).Msgf("broadcasting heartbeat message")
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

func (n *node) sendDataRequest(peer, key string) (string, error) {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending data request message to %v", peer)

	requestID := xid.New().String()

	dataRequestMessage := types.DataRequestMessage{
		RequestID: requestID,
		Key:       key,
	}

	msg, err := marshalMessage(dataRequestMessage)
	if err != nil {
		return "", err
	}

	err = n.Unicast(peer, msg)
	if err != nil {
		return "", err
	}

	return requestID, nil
}

func (n *node) sendDataReply(peer, requestID, key string, data []byte) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending data reply message to %v", peer)

	dataReplyMessage := types.DataReplyMessage{
		RequestID: requestID,
		Key:       key,
		Value:     data,
	}

	msg, err := marshalMessage(dataReplyMessage)
	if err != nil {
		return err
	}

	err = n.Unicast(peer, msg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) forwardSearchRequest(origin, peer string, budget uint, reg regexp.Regexp, requestID string) error {
	pattern := reg.String()

	searchRequestMessage := types.SearchRequestMessage{
		RequestID: requestID,
		Origin:    origin,
		Pattern:   pattern,
		Budget:    budget,
	}

	msg, err := marshalMessage(searchRequestMessage)
	if err != nil {
		return err
	}
	err = n.Unicast(peer, msg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) sendSearchRequestMessage(peer string, budget uint, reg regexp.Regexp) (string, error) {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending search request message to %v", peer)
	requestID := xid.New().String()
	origin := n.myAddr
	err := n.forwardSearchRequest(origin, peer, budget, reg, requestID)
	if err != nil {
		return "", err
	}

	return requestID, nil
}

func (n *node) sendSearchReplyMessage(searchOrigin, dest string, searchReplyMessage types.SearchReplyMessage) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending search reply message to %v via %v", searchOrigin, dest)
	msg, err := marshalMessage(searchReplyMessage)
	if err != nil {
		return err
	}

	// make header
	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		searchOrigin,
		0,
	)

	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	// send to destination
	err = n.route(dest, pkt)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) waitForAckOrResend(pkt transport.Packet) {
	pktID := pkt.Header.PacketID

	_, ok := n.notfify.WaitSingle(pktID, n.conf.AckTimeout)
	if ok {
		log.Info().Str("peerAddr", n.myAddr).Msgf("received ack from %v", pkt.Header.Destination)
		return
	}

	log.Warn().Str("peerAddr", n.myAddr).Msgf("did not receive ack from %v - resending", pkt.Header.Destination)
	// send message to another neighbor
	// get another neighbor
	randomNeighborAddr, ok := n.routingTable.GetRandomNeighbor(n.myAddr, pkt.Header.Destination)
	if !ok {
		return
	}

	// log.Warn().Str("peerAddr", n.myAddr).Msgf("did not receive ack from %v", pkt.Header.Destination)

	newPkt := pkt.Copy()

	header := transport.NewHeader(
		n.myAddr,
		n.myAddr,
		randomNeighborAddr,
		0,
	)

	newPkt.Header = &header

	err := n.conf.Socket.Send(randomNeighborAddr, newPkt, 0)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr)
	}
}

func (n *node) sendPaxosPromiseMessage(dest string, paxosPrepareMessage types.PaxosPrepareMessage) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending Paxos Promise")
	step := paxosPrepareMessage.Step

	paxosPromiseMessage := types.PaxosPromiseMessage{
		Step: step,
		ID:   paxosPrepareMessage.ID,
	}

	paxosInstance, _ := n.multiPaxos.getPaxosInstance(step)

	// if a value was already accepted, relay it
	if paxosInstance.AcceptedValue != nil {
		paxosPromiseMessage.AcceptedValue = paxosInstance.AcceptedValue
		paxosPromiseMessage.AcceptedID = paxosInstance.AcceptedID
	}

	// send private message
	paxosPromiseTransportMessage, err := marshalMessage(paxosPromiseMessage)
	if err != nil {
		return err
	}

	recipients := make(map[string]struct{})
	recipients[dest] = struct{}{}

	privateMessage := types.PrivateMessage{
		Recipients: recipients,
		Msg:        &paxosPromiseTransportMessage,
	}

	msg, err := marshalMessage(privateMessage)
	if err != nil {
		return err
	}

	err = n.Broadcast(msg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) sendPaxosAcceptMessage(paxosProposeMessage types.PaxosProposeMessage) error {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending Paxos Accept")
	paxosAcceptMessage := types.PaxosAcceptMessage{
		Step:  paxosProposeMessage.Step,
		ID:    paxosProposeMessage.ID,
		Value: paxosProposeMessage.Value,
	}

	msg, err := marshalMessage(paxosAcceptMessage)
	if err != nil {
		return err
	}

	err = n.Broadcast(msg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) sendPaxosPrepareMessage() error {

	return nil
}
