package saferoutingtable

import (
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/cs438/peer"
)

type SafeRoutingTable interface {
	SetEntry(origin, relayAddr string)
	GetEntry(origin string) string
	RemoveEntry(origin string)
	GetRoutingTable() peer.RoutingTable
	GetRandomNeighbor(myAddr string) string
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
	r.routingTable[origin] = relayAddr
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
	return r.routingTable
}

// Gets a random neighbor that is not the address passed
func (r *safeRoutingTable) GetRandomNeighbor(myAddr string) string {
	neighborsSet := make(map[string]struct{})

	for key := range r.routingTable {
		neighborsSet[r.routingTable[key]] = struct{}{}
	}

	neighborsList := make([]string, 0)

	for key := range neighborsSet {
		neighborsList = append(neighborsList, key)
	}

	// don't consider myself a neighbor
	// -> this node will process the message either way
	delete(neighborsSet, myAddr)

	rand.Seed(time.Now().UnixNano())
	// neighbors struct
	randNeighborIdx := rand.Intn(len(neighborsList))

	return neighborsList[randNeighborIdx]
}
