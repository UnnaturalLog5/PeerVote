package impl

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

func (n *node) Upload(data io.Reader) (string, error) {
	// process chunk by chunk
	// for each chunk
	//	compute hash
	//	store chunk using hash as key in datablobstore
	//	append to metahash: chunk hash and sep (sep only if it's not the last)
	// calculate metafilekey
	// hash all hashes of file

	metaFileKey := crypto.SHA256.New()
	metaFile := new(bytes.Buffer)

	for {
		chunkHash := crypto.SHA256.New()

		chunkData := make([]byte, n.conf.ChunkSize)
		bytesRead, err := data.Read(chunkData)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil
		}
		// prevent zero-padding the last chunk
		chunkData = chunkData[:bytesRead]

		// write a separator to the metafile, unless it's the first chunk
		if metaFile.Len() != 0 {
			metaFile.Write([]byte(peer.MetafileSep))
		}

		//	compute chunk's hash
		chunkHash.Write(chunkData)
		chunkHashBytes := chunkHash.Sum(nil)

		chunkHashHex := hex.EncodeToString(chunkHashBytes)

		n.dataBlobStore.Set(chunkHashHex, chunkData)

		metaFile.Write([]byte(chunkHashHex))
		metaFileKey.Write(chunkHashBytes)
	}

	metaFileKeyHex := hex.EncodeToString(metaFileKey.Sum(nil))
	n.dataBlobStore.Set(metaFileKeyHex, metaFile.Bytes())
	return metaFileKeyHex, nil
}

func (n *node) retrieveDataFromPeer(key string) ([]byte, error) {
	peers, ok := n.getPeersForData(key)
	if !ok {
		return make([]byte, 0), errors.New("can't retrieve data from peer - no known peers")
	}

	randPeerInt := rand.Intn(len(peers))
	peer := peers[randPeerInt]

	log.Info().Str("peerAddr", n.myAddr).Msgf("need a chunk - requesting from peer %v", peer)

	noRetries := n.conf.BackoffDataRequest.Retry
	backoffFactor := n.conf.BackoffDataRequest.Factor
	initialBackoff := n.conf.BackoffDataRequest.Initial

	for i := uint(0); i < noRetries; i++ {
		// send data request
		// calculate waitTime
		waitTime := initialBackoff * time.Duration(math.Pow(float64(backoffFactor), float64(i)))

		requestID, err := n.sendDataRequest(peer, key)
		if err != nil {
			return make([]byte, 0), err
		}

		// wait for answer
		data, ok := n.timers.WaitSingle(requestID, waitTime)
		if ok {
			chunk := data.([]byte)

			if len(chunk) == 0 {
				// remove peer from catalog for this chunk
				// if they returned an empty chunk
				n.removePeerFromCatalog(key, peer)
				return make([]byte, 0), errors.New("peer answered with empty message")
			}

			return chunk, nil
		}
		// if timer runs out
		// resend with backoff
		// in next iteration

		return make([]byte, 0), nil
	}

	return make([]byte, 0), nil
}

func (n *node) Download(metahash string) ([]byte, error) {
	var err error
	metaFile := n.dataBlobStore.Get(metahash)

	if metaFile == nil {
		// retrieve from other peers
		metaFile, err = n.retrieveDataFromPeer(metahash)
		if err != nil {
			return make([]byte, 0), err
		}
	}

	chunkHexKeys := strings.Split(string(metaFile), peer.MetafileSep)

	data := new(bytes.Buffer)

	for _, chunkHexKey := range chunkHexKeys {
		// try to get locally
		chunk := n.dataBlobStore.Get(chunkHexKey)
		if chunk == nil {
			// retrieve from other peers, if not found locally
			chunk, err = n.retrieveDataFromPeer(chunkHexKey)
			if err != nil {
				return make([]byte, 0), err
			}
		}

		// combine data
		_, err := data.Write(chunk)
		if err != nil {
			return make([]byte, 0), err
		}
	}

	return data.Bytes(), nil
}

func (n *node) SearchAll(reg regexp.Regexp, budget uint, timeout time.Duration) ([]string, error) {
	// get peers
	peers := n.routingTable.GetNeighborsList(n.myAddr)

	// distribute search budget
	peerBudgets := getPeerBudgets(peers, budget)

	metaSearchKey := n.timers.SetUpMultiple(timeout)

	// send requestmessage
	for peer, budget := range peerBudgets {
		requestID, err := n.sendSearchRequestMessage(peer, budget, reg)
		if err != nil {
			log.Err(err).Str("peerAddr", n.myAddr).Msg("problem sending on of the search request messages")
		}

		// register requestID
		n.timers.Register(metaSearchKey, requestID)
	}

	// wait for responses
	responses := n.timers.WaitMultiple(metaSearchKey)

	namesSet := make(map[string]struct{}, 0)

	// fileInfos := make([]types.FileInfo, 0)
	for _, response := range responses {
		// type assertion -> this could go wrong if unexpected data is sent
		for _, result := range response.([]types.FileInfo) {
			// fileInfo := result.(types.FileInfo)
			fileInfo := result

			// treat like set
			namesSet[fileInfo.Name] = struct{}{}
		}
	}

	n.namingStore.ForEach(func(name string, val []byte) bool {
		// ignore this entry if the regex doesn't give any matches
		if !reg.MatchString(name) {
			return true
		}

		namesSet[name] = struct{}{}

		return true
	})

	names := make([]string, 0)
	for name := range namesSet {
		names = append(names, name)
	}

	return names, nil
}

func (n *node) SearchFirst(pattern regexp.Regexp, conf peer.ExpandingRing) (string, error) {
	return "", nil
}

// distribute budget to peers
func getPeerBudgets(peers []string, budget uint) map[string]uint {
	peerBudgets := make(map[string]uint)

	// never divide by zero!
	if len(peers) == 0 {
		return peerBudgets
	}

	budgetPerPeer := budget / uint(len(peers))
	budgetLeftOfer := budget % uint(len(peers))

	for i, peer := range peers {
		peerBudget := uint(0)

		// see if peer gets a part of the left-over budget
		if int(budgetLeftOfer)-i > 0 {
			peerBudget = budgetPerPeer + 1
		} else {
			peerBudget = budgetPerPeer
		}

		// only include peer if it has a non-zero budget
		if peerBudget > 0 {
			peerBudgets[peer] = peerBudget
		}
	}

	return peerBudgets
}
