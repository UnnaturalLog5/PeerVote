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

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/peer"
)

func (n *node) Upload(data io.Reader) (metahash string, err error) {
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

	log.Info().Str("peerAddr", n.myAddr).Msgf("need chunk %v, requesting from peer %v", key, peer)

	noRetries := n.conf.BackoffDataRequest.Retry
	backoffFactor := n.conf.BackoffDataRequest.Factor
	initialBackoff := n.conf.BackoffDataRequest.Initial

	for i := uint(0); i < noRetries; i++ {
		// send data request
		requestID := xid.New().String()

		// calculate waitTime
		waitTime := initialBackoff * time.Duration(math.Pow(float64(backoffFactor), float64(i)))

		requestID, err := n.sendDataRequest(requestID, peer, key)
		if err != nil {
			return make([]byte, 0), err
		}

		// wait for answer
		data, ok := n.timers.Wait(requestID, waitTime)
		if ok {
			return data.([]byte), nil
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

func (n *node) Tag(name string, mh string) error {
	return nil
}

func (n *node) Resolve(name string) (metahash string) {
	return ""
}

func (n *node) SearchAll(reg regexp.Regexp, budget uint, timeout time.Duration) (names []string, err error) {
	return make([]string, 0), nil
}

func (n *node) SearchFirst(pattern regexp.Regexp, conf peer.ExpandingRing) (name string, err error) {
	return "", nil
}
