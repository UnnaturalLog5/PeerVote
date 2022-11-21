package impl

import (
	"errors"
	"regexp"
	"strings"

	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
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

	mhBytesExisting := n.namingStore.Get(name)
	if mhBytesExisting != nil {
		return errors.New("metahash already exists")
	}

	ok := n.findPaxosConsensus(name, mh)
	if !ok {
		return errors.New("error finding consensus")
	}

	n.namingStore.Set(name, mhBytes)

	return nil
}

func (n *node) Resolve(name string) (metahash string) {
	mhBytes := n.namingStore.Get(name)

	return string(mhBytes)
}

func (n *node) getFileInfos(reg regexp.Regexp) []types.FileInfo {
	fileInfos := make([]types.FileInfo, 0)

	// iterate through the items we have stored
	n.namingStore.ForEach(func(key string, val []byte) bool {
		// ignore this entry if the regex doesn't give any matches
		if !reg.MatchString(key) {
			return true
		}

		metahash := string(val)

		metaFile := n.dataBlobStore.Get(metahash)
		if metaFile == nil {
			// skip this name, if the metahash isn't in the blobstore
			return true
		}

		chunkKeys := strings.Split(string(metaFile), peer.MetafileSep)
		chunks := make([][]byte, 0)

		for _, chunkKey := range chunkKeys {
			chunk := n.dataBlobStore.Get(chunkKey)
			// missing chunks are nil

			if chunk != nil {
				chunks = append(chunks, []byte(chunkKey))
			} else {
				chunks = append(chunks, nil)
			}

		}

		// construct FileInfo file
		fileInfo := types.FileInfo{
			Name:     key,
			Metahash: metahash,
			Chunks:   chunks,
		}

		fileInfos = append(fileInfos, fileInfo)

		// n.dataBlobStore.Get()
		return true
	})

	return fileInfos
}
