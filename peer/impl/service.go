package impl

import (
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
)

func (n *node) receiveLoop() {
	log.Info().Str("peerAddr", n.myAddr).Msg("peer started listening")

	for {
		select {
		case <-n.stopPeer:
			return
		default:
			pkt, err := n.conf.Socket.Recv(time.Second * 1)
			if errors.Is(err, transport.TimeoutError(0)) {
				continue
			}
			if err != nil {
				log.Err(err).Str("peerAddr", n.myAddr).Msg("error receiving packet")
				continue
			}

			// asynchronously handle packet
			go n.handlePacket(pkt)
		}
	}
}

func (n *node) sendStatusMessageLoop() {
	go func() {
		for {
			select {
			case <-n.stopStatusTicker:
				return
			case <-n.statusTicker.C:
				// send status message
				err := n.sendStatusMessage("")
				if err != nil {
					log.Err(err).Str("peerAddr", n.myAddr).Msg("did not send status message")
				}
			}
		}
	}()
}

func (n *node) sendHeartbeatLoop() {
	go func() {
		for {
			select {
			case <-n.stopHeartbeatTicker:
				return
			case <-n.heartbeatTicker.C:
				// send status message
				log.Info().Str("peerAddr", n.myAddr).Msg("Send heartbeat broadcast")

				err := n.sendHeartbeat()
				if err != nil {
					log.Err(err).Str("peerAddr", n.myAddr).Msg("error sending heartbeat message")
				}
			}
		}
	}()
}

// Start implements peer.Service
func (n *node) Start() error {
	// start listening asynchronously
	go n.receiveLoop()

	// send status message regularly
	// but only if the interval is > 0
	if n.conf.AntiEntropyInterval > 0 {
		n.statusTicker = time.NewTicker(n.conf.AntiEntropyInterval)
		go n.sendStatusMessageLoop()
	}

	// regularly send heartbeat
	if n.conf.HeartbeatInterval > 0 {
		n.heartbeatTicker = time.NewTicker(n.conf.HeartbeatInterval)
		go n.sendHeartbeatLoop()
	}

	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// properly close all timers and channels

	if n.conf.AntiEntropyInterval > 0 {
		n.stopStatusTicker <- struct{}{}
		close(n.stopStatusTicker)
		n.statusTicker.Stop()
	}

	if n.conf.HeartbeatInterval > 0 {
		n.stopHeartbeatTicker <- struct{}{}
		close(n.stopHeartbeatTicker)
		n.heartbeatTicker.Stop()
	}

	n.stopPeer <- struct{}{}
	close(n.stopPeer)

	log.Info().Str("peerAddr", n.myAddr).Msg("peer is shutting down")
	return nil
}

func (n *node) handlePacket(pkt transport.Packet) {
	// forward packet if it's not meant for this node
	myAddr := n.conf.Socket.GetAddress()
	if pkt.Header.Destination != myAddr {
		log.Info().Str("peerAddr", n.myAddr).Msgf("forwarded packet meant for peer %v", pkt.Header.Destination)

		err := n.forward(pkt.Header.Destination, pkt)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("error forwarding packet")
		}

		return
	}

	// do something with the pkt
	// log.Info().Str("peerAddr", n.myAddr).Msgf("received packet")
	err := n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msg("error handling packet")
		return
	}
}

// AddPeer implements peer.Messaging
func (n *node) AddPeer(addr ...string) {
	for _, newAddr := range addr {
		n.routingTable.SetEntry(newAddr, newAddr)
	}

	// n.sequenceStore. TODO add entry?
}

// GetRoutingTable implements peer.Messaging
func (n *node) GetRoutingTable() peer.RoutingTable {
	routingTable := n.routingTable.GetRoutingTable()

	routingTableCopy := make(peer.RoutingTable)

	for key, value := range routingTable {
		routingTableCopy[key] = value
	}

	return routingTableCopy
}

// SetRoutingEntry implements peer.Messaging
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
