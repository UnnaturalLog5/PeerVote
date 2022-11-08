package impl

import (
	"go.dedis.ch/cs438/peer"
)

func (n *node) GetCatalog() peer.Catalog {
	n.catalogMutex.RLock()
	defer n.catalogMutex.RUnlock()

	return n.catalog
}

func (n *node) UpdateCatalog(key string, peer string) {
	n.catalogMutex.Lock()
	defer n.catalogMutex.Unlock()

	// if there is no entry, create the corresponding map
	_, ok := n.catalog[key]
	if !ok {
		n.catalog[key] = make(map[string]struct{})
	}

	n.catalog[key][peer] = struct{}{}
}

func (n *node) removePeerFromCatalog(key string, peer string) {
	n.catalogMutex.Lock()
	defer n.catalogMutex.Unlock()

	// if there is no entry, create the corresponding map
	_, ok := n.catalog[key]
	if !ok {
		n.catalog[key] = make(map[string]struct{})
	}

	delete(n.catalog[key], peer)
}

func (n *node) getPeersForData(key string) ([]string, bool) {
	n.catalogMutex.Lock()
	defer n.catalogMutex.Unlock()

	peersMap := n.catalog[key]

	peers := make([]string, 0)

	for peer := range peersMap {
		peers = append(peers, peer)
	}

	if len(peers) > 0 {
		return peers, true
	}

	return nil, false
}

func (n *node) Tag(name string, mh string) error {
	mhBytes := []byte(mh)

	n.namingStore.Set(name, mhBytes)

	return nil
}

func (n *node) Resolve(name string) (metahash string) {
	mhBytes := n.namingStore.Get(name)

	return string(mhBytes)
}