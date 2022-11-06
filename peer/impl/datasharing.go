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

// func (n *node) retrieveLocalData(metaFile []byte) ([]byte, error) {

// 	return data.Bytes(), nil
// }

func (n *node) retrieveDataFromPeer(peer, key string) ([]byte, error) {
	noRetries := n.conf.BackoffDataRequest.Retry
	backoffFactor := n.conf.BackoffDataRequest.Factor
	initialBackoff := n.conf.BackoffDataRequest.Initial

	for i := uint(0); i < noRetries; i++ {
		// send data request
		err := n.sendDataRequest(peer, key)
		if err != nil {
			return make([]byte, 0), err
		}

		// wait for
		waitTime := initialBackoff * time.Duration(math.Pow(float64(backoffFactor), float64(i)))

		// wait for answer
		n.timers.Set(key, waitTime)

		n.timers.Wait(key)
		// if timer runs out
		// resend with backoff
	}

	return make([]byte, 0), nil
}

func (n *node) Download(metahash string) ([]byte, error) {
	metaFile := n.dataBlobStore.Get(metahash)

	if metaFile != nil {
		// retrieve from other peers

		return make([]byte, 0), errors.New("could not retrieve file - this metahash is not known locally" + metahash)
		// retrieve locally
		// return n.retrieveLocalData(metaFile)
	}

	chunkHexKeys := strings.Split(string(metaFile), peer.MetafileSep)

	data := new(bytes.Buffer)

	retrievedChunks := make(map[string][]byte)

	for _, chunkHexKey := range chunkHexKeys {
		chunk := n.dataBlobStore.Get(chunkHexKey)

		if chunk != nil {
			retrievedChunks[chunkHexKey] = chunk
		}

		peers := n.getPeersForData(chunkHexKey)
		randPeerInt := rand.Intn(len(peers))
		peer := peers[randPeerInt]

		chunk, err := n.retrieveDataFromPeer(peer, chunkHexKey)
		if err != nil {
			return make([]byte, 0), err
		}

		// combine data
		_, err = data.Write(chunk)
		if err != nil {
			return make([]byte, 0), err
		}

		return data.Bytes(), nil
	}

	// if not available locally or on other peers
	// return error if metahash can't be found
	// return data.Bytes(), nil
	return make([]byte, 0), errors.New("could not retrieve file - this metahash is unknown " + metahash)
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
