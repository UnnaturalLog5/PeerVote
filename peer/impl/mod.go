package impl

import (
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/asyncnotify"
	"go.dedis.ch/cs438/peer/impl/electionstore"
	"go.dedis.ch/cs438/peer/impl/routingtable"
	"go.dedis.ch/cs438/peer/impl/rumorstore"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/types"
)

var (
	// defaultLevel can be changed to set the desired level of the logger
	defaultLevel = zerolog.InfoLevel
	// defaultLevel = zerolog.ErrorLevel

	// log.ut is the logger configuration
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

	notify := asyncnotify.New()

	dataBlobStore := conf.Storage.GetDataBlobStore()
	namingStore := conf.Storage.GetNamingStore()
	blockStore := conf.Storage.GetBlockchainStore()
	electionStore := electionstore.New()

	catalog := make(peer.Catalog)

	paxosInstances := make(map[uint]*paxosInstance)
	threshold := uint(conf.PaxosThreshold(conf.TotalPeers))

	peer := node{
		conf:                conf,
		routingTable:        routingTable,
		started:             false,
		stopPeer:            stopPeer,
		stopStatusTicker:    stopStatusTicker,
		myAddr:              myAddr,
		rumorStore:          rumorStore,
		stopHeartbeatTicker: stopHeartbeatTicker,
		notfify:             notify,
		dataBlobStore:       dataBlobStore,
		namingStore:         namingStore,
		catalog:             catalog,
		knownRequests:       sync.Map{},
		blockStore:          blockStore,
		paxosInstances:      paxosInstances,
		threshold:           threshold,
		electionStore:       electionStore,
	}

	// register Callbacks
	peer.conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, peer.HandleChatMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, peer.HandleRumorsMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, peer.HandleAckMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, peer.HandleStatusMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, peer.HandlePrivateMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, peer.HandleEmptyMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.DataReplyMessage{}, peer.HandleDataReplyMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.DataRequestMessage{}, peer.HandleDataRequestMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.SearchReplyMessage{}, peer.HandleSearchReplyMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.SearchRequestMessage{}, peer.HandleSearchRequestMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.PaxosPrepareMessage{}, peer.HandlePaxosPrepareMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.PaxosPromiseMessage{}, peer.HandlePaxosPromiseMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.PaxosProposeMessage{}, peer.HandlePaxosProposeMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.PaxosAcceptMessage{}, peer.HandlePaxosAcceptMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.TLCMessage{}, peer.HandleTLCMessage)

	peer.conf.MessageRegistry.RegisterMessageCallback(types.AnnounceElectionMessage{}, peer.HandleAnnounceElectionMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.VoteMessage{}, peer.HandleVoteMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.ResultMessage{}, peer.HandleResultMessage)

	// Pedersen DKG
	peer.conf.MessageRegistry.RegisterMessageCallback(types.DKGShareMessage{}, peer.HandleDKGShareMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.DKGShareValidationMessage{}, peer.HandleDKGShareValidationMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.ElectionReadyMessage{}, peer.HandleElectionReadyMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.DKGRevealShareMessage{}, peer.HandleDKGRevealShareMessage)
	peer.conf.MessageRegistry.RegisterMessageCallback(types.StartElectionMessage{}, peer.HandleStartElectionMessage)

	return &peer
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer

	// sending a message on this channel will stop the node after it has been started
	stopPeer chan struct{}
	started  bool

	conf         peer.Configuration
	routingTable routingtable.RoutingTable

	rumorStore rumorstore.RumorStore

	statusTicker     *time.Ticker
	stopStatusTicker chan struct{}

	heartbeatTicker     *time.Ticker
	stopHeartbeatTicker chan struct{}

	myAddr string

	// maps from packet ID to timer
	notfify asyncnotify.AsyncNotify

	// dataSharing entities
	dataBlobStore storage.Store
	namingStore   storage.Store
	catalog       peer.Catalog
	catalogMutex  sync.RWMutex

	knownRequests sync.Map

	// paxos
	paxosLock sync.RWMutex
	// paxos instances
	threshold      uint
	paxosInstances map[uint]*paxosInstance
	step           uint

	blockStore storage.Store

	electionStore electionstore.ElectionStore
}

// IsElectionStarted checks if the election started (that is, one of the trusted mixnet
// servers initiated the election and the peer is allowed to cast a vote)
func (n *node) IsElectionStarted(election types.Election) bool {
	if election.Base.ElectionReadyCnt != len(election.Base.MixnetServers) {
		return false
	}
	initiator := n.GetFirstQualifiedInitiator(election)
	_, exists := election.Base.Initiators[initiator]
	return exists
}

// GetFirstQualifiedInitiator returns the ID of the mixnet server which is responsible for
// initiating the election
func (n *node) GetFirstQualifiedInitiator(election types.Election) string {
	for i := 0; i < len(election.Base.MixnetServersPoints); i++ {
		if election.Base.MixnetServersPoints[i] > n.conf.PedersenSuite.T {
			return election.Base.MixnetServers[i]
		}
	}
	return ""
}
