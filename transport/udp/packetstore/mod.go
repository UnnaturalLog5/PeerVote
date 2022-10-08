package packetstore

import (
	"sync"

	"go.dedis.ch/cs438/transport"
)

type PacketStore interface {
	Append(pkt transport.Packet)
	Get() []transport.Packet
}

func New() PacketStore {
	ps := packetStore{}
	return &ps
}

type packetStore struct {
	sync.RWMutex
	items []transport.Packet
}

func (p *packetStore) Append(pkt transport.Packet) {
	p.Lock()
	defer p.Unlock()
	p.items = append(p.items, pkt)
}

func (p *packetStore) Get() []transport.Packet {
	p.RLock()
	defer p.RUnlock()

	return p.items
}
