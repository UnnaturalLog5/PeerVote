package impl

import (
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/handler"
	"go.dedis.ch/cs438/peer/impl/saferoutingtable"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	routingTable := saferoutingtable.New()

	// set routing entry for own address
	// use routingTable directly as n.routingTable.SetEntry() prevents overwriting the node's own address
	myAddr := conf.Socket.GetAddress()
	routingTable.SetEntry(myAddr, myAddr)

	peer := node{
		conf:         conf,
		routingTable: routingTable,
		stop:         make(chan struct{}),
	}

	// register Callbacks
	peer.conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, handler.ChatMessage)

	return &peer
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	// You probably want to keep the peer.Configuration on this struct:
	conf         peer.Configuration
	routingTable saferoutingtable.SafeRoutingTable

	// sending a message on this channel will stop the node after it has been started
	stop chan struct{}
}

// Start implements peer.Service
func (n *node) Start() error {
	// start listening asynchronously
	go func() {
		log.Info().Msg("peer started listening")

		for {
			select {
			case <-n.stop:
				return
			default:
				pkt, err := n.conf.Socket.Recv(time.Second * 1)
				if errors.Is(err, transport.TimeoutError(0)) {
					continue
				}
				if err != nil {
					log.Err(err).Msg("error receiving packet")
					continue
				}

				// asynchronously handle packet
				go n.handlePacket(pkt)
			}
		}
	}()

	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	n.stop <- struct{}{}

	log.Info().Msg("peer is shutting down")
	return nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	myAddr := n.conf.Socket.GetAddress()

	// make header
	header := transport.NewHeader(
		myAddr,
		myAddr,
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

// receive packet
func (n *node) handlePacket(pkt transport.Packet) {
	// forward packet if it's not meant for this node
	myAddr := n.conf.Socket.GetAddress()
	if pkt.Header.Destination != myAddr {
		log.Info().Msgf("forwarded packet meant for peer %v", pkt.Header.Destination)

		err := n.forward(pkt.Header.Destination, pkt)
		if err != nil {
			log.Err(err).Msg("error handling packet")
			return
		}

		return
	}

	// do something with the pkt
	log.Info().Msgf("received packet")
	err := n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		log.Err(err).Msg("error handling packet")
		return
	}
}

// forward packet
func (n *node) forward(dest string, pkt transport.Packet) error {
	relayPkt := pkt.Copy()

	// update packet header with this peer's address
	myAddr := n.conf.Socket.GetAddress()
	relayPkt.Header.RelayedBy = myAddr

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

// AddPeer implements peer.Service
func (n *node) AddPeer(addr ...string) {
	for _, newAddr := range addr {
		n.routingTable.SetEntry(newAddr, newAddr)
	}
}

// GetRoutingTable implements peer.Service
func (n *node) GetRoutingTable() peer.RoutingTable {
	return n.routingTable.GetRoutingTable()
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	// should a node be able to change its own entry?
	// probably not, but only after it has been set once!
	// that first time is essential
	if origin == n.conf.Socket.GetAddress() {
		return
	}

	// remove element if it points nowhere
	if relayAddr == "" {
		n.routingTable.RemoveEntry(origin)
	} else {
		n.routingTable.SetEntry(origin, relayAddr)
	}
}
