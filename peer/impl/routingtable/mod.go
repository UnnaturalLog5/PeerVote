package routingtable

import (
	"math/rand"
	"sync"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
)

type RoutingTable interface {
	// Set an entry of the routing table
	// but only of origin is not already a neighbor
	SetEntry(origin, relayAddr string)

	// Get an entry of the routing table
	GetEntry(origin string) string

	// Remove an entry of the routing table
	RemoveEntry(origin string)

	// Get a copy of the underlying routingTable
	GetRoutingTable() peer.RoutingTable

	// Gets a random neighbor except those peers that are passed in
	// returns an error, when no neighbor can be found
	GetRandomNeighbor(forbiddenPeers ...string) (string, bool)

	// get all neighbors except the ones passed in as arguments
	GetNeighborsList(forbiddenPeers ...string) []string
}

type routingTable struct {
	sync.RWMutex
	routingTable peer.RoutingTable
}

func New() RoutingTable {
	innerRoutingTable := make(peer.RoutingTable)

	return &routingTable{
		routingTable: innerRoutingTable,
	}
}

// Implements RoutingTable
func (r *routingTable) SetEntry(origin, relayAddr string) {
	r.Lock()
	defer r.Unlock()

	// only update if not already neighbor
	if origin != r.routingTable[origin] {
		log.Info().Msgf("updating routing table entry %v, old: %v, new: %v", origin, r.routingTable[origin], relayAddr)
		r.routingTable[origin] = relayAddr
	}
}

// Implements RoutingTable
func (r *routingTable) GetEntry(origin string) string {
	r.RLock()
	defer r.RUnlock()
	return r.routingTable[origin]
}

// Implements RoutingTable
func (r *routingTable) RemoveEntry(origin string) {
	r.Lock()
	defer r.Unlock()
	delete(r.routingTable, origin)
}

// Implements RoutingTable
func (r *routingTable) GetRoutingTable() peer.RoutingTable {
	r.RLock()
	defer r.RUnlock()
	routingTableCopy := make(peer.RoutingTable)

	for k, v := range r.routingTable {
		routingTableCopy[k] = v
	}

	return routingTableCopy
}

// Gets a random neighbor that is not the address passed
func (r *routingTable) GetRandomNeighbor(forbiddenPeers ...string) (string, bool) {
	r.RLock()
	defer r.RUnlock()

	neighborsList := r.GetNeighborsList(forbiddenPeers...)

	// neighbors struct
	if len(neighborsList) == 0 {
		return "", false
	}

	randNeighborIdx := rand.Intn(len(neighborsList))
	return neighborsList[randNeighborIdx], true
}

// gets a list of neighbors without forbiddenPeers
func (r *routingTable) GetNeighborsList(forbiddenPeers ...string) []string {
	r.RLock()
	defer r.RUnlock()

	neighborsSet := make(map[string]struct{})

	for key := range r.routingTable {
		neighborsSet[r.routingTable[key]] = struct{}{}
	}

	// -> don't choose forbidden neighbors!
	// so we don't choose the node itself
	// or another node that we may have already sent the same message to
	for _, forbiddenPeer := range forbiddenPeers {
		delete(neighborsSet, forbiddenPeer)
	}

	neighborsList := make([]string, 0)

	for key := range neighborsSet {
		neighborsList = append(neighborsList, key)
	}

	return neighborsList
}
