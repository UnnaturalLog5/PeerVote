package impl

import (
	"errors"
	"time"

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

	routingTable := saferoutingtable.New()
	routingTable.SetEntry(myAddr, myAddr)

	peer := node{
		conf:         conf,
		routingTable: routingTable,
	}

	// peer.conf.MessageRegistry.RegisterMessageCallback()

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

var stop chan struct{} = make(chan struct{})

// Start implements peer.Service
func (n *node) Start() error {
	// start listening asynchronously
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				pkt, err := n.conf.Socket.Recv(time.Second * 1)
				if errors.Is(err, transport.TimeoutError(0)) {
					continue
				}
				if err != nil {
					return
				}

				// do something with the pkt
				n.conf.MessageRegistry.ProcessPacket(pkt)
			}
		}
	}()

	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	stop <- struct{}{}

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

	// make packet
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
