package saferoutingtable

import (
	"sync"

	"go.dedis.ch/cs438/peer"
)

type SafeRoutingTable interface {
	SetEntry(origin, relayAddr string)
	GetEntry(origin string) string
	RemoveEntry(origin string)
	GetRoutingTable() peer.RoutingTable
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
