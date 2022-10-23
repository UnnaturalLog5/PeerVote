package impl

import (
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/acktimers"
	"go.dedis.ch/cs438/peer/impl/routingtable"
	"go.dedis.ch/cs438/peer/impl/rumorstore"
	"go.dedis.ch/cs438/types"
)

var (
	// defaultLevel can be changed to set the desired level of the logger
	defaultLevel = zerolog.InfoLevel

	// logout is the logger configuration
	logout = zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}
)

func init() {
	zerolog.CallerMarshalFunc = func(file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
		return file + ":" + strconv.Itoa(line)
	}

	log.Logger = zerolog.New(logout).
		Level(defaultLevel).
		With().
		Timestamp().
		Caller().
		Logger()
}

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	log.Info()

	// seed once when we start the peer for all following pseudo-random operations
	rand.Seed(time.Now().UnixNano())

	routingTable := routingtable.New()

	// set routing entry for own address
	// use routingTable directly as n.routingTable.SetEntry() prevents overwriting the node's own address
	myAddr := conf.Socket.GetAddress()
	routingTable.SetEntry(myAddr, myAddr)

	stopPeer := make(chan struct{})
	stopStatusTicker := make(chan struct{})
	stopHeartbeatTicker := make(chan struct{})

	rumorStore := rumorstore.New()

	ackTimers := acktimers.New()

	peer := node{
		conf:                conf,
		routingTable:        routingTable,
		stopPeer:            stopPeer,
		stopStatusTicker:    stopStatusTicker,
		myAddr:              myAddr,
		rumorStore:          rumorStore,
		stopHeartbeatTicker: stopHeartbeatTicker,
		ackTimers:           ackTimers,
	}

	// register Callbacks
	peer.conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, peer.HandleChatMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, peer.HandleRumorsMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, peer.HandleAckMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, peer.HandleStatusMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, peer.HandlePrivateMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, peer.HandleEmptyMessage)

	return &peer
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	// sending a message on this channel will stop the node after it has been started
	stopPeer chan struct{}

	conf         peer.Configuration
	routingTable routingtable.RoutingTable

	rumorStore rumorstore.RumorStore

	statusTicker     *time.Ticker
	stopStatusTicker chan struct{}

	heartbeatTicker     *time.Ticker
	stopHeartbeatTicker chan struct{}

	myAddr string

	// maps from packet ID to timer
	ackTimers acktimers.AckTimers
}
