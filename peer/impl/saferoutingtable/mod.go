package saferoutingtable

import (
	"errors"
	"math/rand"
	"sync"

	"go.dedis.ch/cs438/peer"
)

type SafeRoutingTable interface {
	// Set an entry of the routing table
	// but only of origin is not already a neighbor
	SetEntry(origin, relayAddr string)

	// Get an entry of the routing table
	GetEntry(origin string) string

	// Remove an entry of the routing table
	RemoveEntry(origin string)

	// Get a copy of the underlying routingTable
	GetRoutingTable() peer.RoutingTable

	// Gets a random neighbor
	GetRandomNeighbor(forbiddenPeers ...string) (string, error)
}

type safeRoutingTable struct {
	sync.RWMutex
	routingTable peer.RoutingTable
}

func New() SafeRoutingTable {
	routingTable := make(peer.RoutingTable)

	safeRoutingTable := safeRoutingTable{
		routingTable: routingTable,
	}

	return &safeRoutingTable
}

// Implements SafeRoutingTable
func (r *safeRoutingTable) SetEntry(origin, relayAddr string) {
	r.Lock()
	defer r.Unlock()

	// only update if not already neighbor
	if origin != r.routingTable[origin] {
		r.routingTable[origin] = relayAddr
	}
}

// Implements SafeRoutingTable
func (r *safeRoutingTable) GetEntry(origin string) string {
	r.RLock()
	defer r.RUnlock()
	return r.routingTable[origin]
}

// Implements SafeRoutingTable
func (r *safeRoutingTable) RemoveEntry(origin string) {
	r.Lock()
	defer r.Unlock()
	delete(r.routingTable, origin)
}

// Implements SafeRoutingTable
func (r *safeRoutingTable) GetRoutingTable() peer.RoutingTable {
	routingTableCopy := make(peer.RoutingTable)

	for k, v := range r.routingTable {
		routingTableCopy[k] = v
	}

	return routingTableCopy
}

// Gets a random neighbor that is not the address passed
func (r *safeRoutingTable) GetRandomNeighbor(forbiddenPeers ...string) (string, error) {
	r.RLock()
	defer r.RUnlock()

	neighborsList := r.getNeighborsList(forbiddenPeers...)

	// neighbors struct
	if len(neighborsList) == 0 {
		return "", errors.New("could not get random neighbor, there is no suitable neighbor")
	}

	randNeighborIdx := rand.Intn(len(neighborsList))
	return neighborsList[randNeighborIdx], nil
}

// gets a list of neighbors without forbiddenPeers
func (r *safeRoutingTable) getNeighborsList(forbiddenPeers ...string) []string {
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
