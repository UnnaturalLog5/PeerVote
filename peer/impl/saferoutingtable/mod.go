package saferoutingtable

import (
	"sync"

	"go.dedis.ch/cs438/peer"
)

type SafeRoutingTable interface {
	SetEntry(origin, relayAddr string)
	GetEntry(origin string) string
	GetRoutingTable() peer.RoutingTable
}

type safeRoutingTable struct {
	sync.RWMutex
	routingTable peer.RoutingTable
}

func NewRoutingTable() SafeRoutingTable {
	routingTable := make(peer.RoutingTable)

	safeRoutingTable := safeRoutingTable{
		routingTable: routingTable,
	}

	return &safeRoutingTable
}

// Implements SafeRoutinTable
func (r *safeRoutingTable) SetEntry(origin, relayAddr string) {
	r.Lock()
	defer r.Unlock()
	r.routingTable[origin] = relayAddr
}

// Implements SafeRoutinTable
func (r *safeRoutingTable) GetEntry(origin string) string {
	r.RLock()
	defer r.RUnlock()
	return r.routingTable[origin]
}

// Implements SafeRoutinTable
func (r *safeRoutingTable) GetRoutingTable() peer.RoutingTable {
	return r.routingTable
}
