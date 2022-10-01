package impl

import (
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/saferoutingtable"
	"go.dedis.ch/cs438/transport"
)

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	// here you must return a struct that implements the peer.Peer functions.
	// Therefore, you are free to rename and change it as you want.

	myAddr := conf.Socket.GetAddress()

	routingTable := saferoutingtable.NewRoutingTable()
	routingTable.SetEntry(myAddr, myAddr)

	peer := node{
		conf:         conf,
		routingTable: routingTable,
	}

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
}

// Start implements peer.Service
func (n *node) Start() error {
	// start listening
	// for {
	// 	pkt, err := n.conf.Socket.Recv(0)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	pkt.
	// }

	// panic("to be implemented in HW0")
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// close socket?
	// panic("to be implemented in HW0")
	return nil
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	panic("to be implemented in HW0")
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
	n.routingTable.SetEntry(origin, relayAddr)
}
