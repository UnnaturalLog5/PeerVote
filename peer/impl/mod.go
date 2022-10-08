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
	// here you must return a struct that implements the peer.Peer functions.
	// Therefore, you are free to rename and change it as you want.

	myAddr := conf.Socket.GetAddress()

	routingTable := saferoutingtable.New()
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
	stop         chan struct{}
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
				err := n.receive()
				if err != nil {
					log.Err(err).Msg("error receiving packet")
				}
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

	// log.Info().Msg(string(msg.Payload))
	// test, _ := msg.Payload.MarshalJSON()
	// log.Info().Msg(string(test))
	// log.Info().Msg(string(msg.Payload))

	// make packet
	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	err := n.route(dest, pkt)
	if err != nil {
		return err
	}

	return nil
}

// receive packet
func (n *node) receive() error {
	pkt, err := n.conf.Socket.Recv(time.Second * 1)
	if errors.Is(err, transport.TimeoutError(0)) {
		return nil
	}
	if err != nil {
		return err
	}

	// forward packet if it's not meant for this node
	myAddr := n.conf.Socket.GetAddress()
	if pkt.Header.Destination != myAddr {
		err := n.forward(pkt.Header.Destination, pkt)
		if err != nil {
			return err
		}
	}

	// do something with the pkt
	err = n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		return err
	}

	return nil
}

// forward packet
func (n *node) forward(dest string, pkt transport.Packet) error {
	relayPkt := pkt.Copy()

	myAddr := n.conf.Socket.GetAddress()
	relayPkt.Header.RelayedBy = myAddr

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
	// if origin == n.conf.Socket.GetAddress() {
	// 	return
	// }

	// remove element if it points nowhere
	if relayAddr == "" {
		n.routingTable.RemoveEntry(origin)
	} else {
		n.routingTable.SetEntry(origin, relayAddr)
	}
}
