package impl

import (
	"crypto"
	"encoding/hex"
	"strconv"
	"sync"

	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/types"
)

func (n *node) findPaxosConsensus(filename, metahash string) bool {
	if n.conf.TotalPeers == 1 {
		return true
	}

	// Phase 1
	for {
		// initialize round
		prepare, ok := n.multiPaxos.PreparePaxos(n.myAddr)
		if !ok {
			return false
		}

		// send prepare
		err := n.sendPaxosPrepareMessage(prepare)
		if err != nil {
			// todo error
			return false
		}

		// wait for promises
		// HandlePromise will notify this waiter
		nextPhase := n.multiPaxos.WaitForNextPhase(n.conf.PaxosProposerRetry)
		if nextPhase {
			break
		}
		// retry after timeout if not successful
	}

	// Phase 2
	for {
		propose := n.multiPaxos.ProposePaxos(filename, metahash)

		err := n.sendPaxosProposeMessage(propose)
		if err != nil {
			// todo log error
			return false
		}

		// wait for accepts
		// HandleAccept will notify this waiter
		success := n.multiPaxos.WaitForNextPhase(n.conf.PaxosProposerRetry)
		if success {
			break
		}
		// retry after timeout if not successful
	}

	// get accepted value
	// acceptedValue := n.multiPaxos.GetAcceptedValue()

	return true
}

type blockchain struct {
	sync.Mutex
	blockStore storage.Store
}

func (b *blockchain) AddBlock(value types.PaxosValue) {
	index := b.blockStore.Len()

	prevHash := b.blockStore.Get(storage.LastBlockKey)

	// H = sha256(Index || v.UniqID || v.Filename || v.Metahash || Prevhash)
	hash := crypto.SHA256.New()
	hash.Write([]byte(strconv.Itoa(index)))
	hash.Write([]byte(value.UniqID))
	hash.Write([]byte(value.Filename))
	hash.Write([]byte(value.Metahash))
	hash.Write(prevHash)
	blockHash := hash.Sum(nil)

	newBlock := types.BlockchainBlock{
		Index:    uint(index),
		Hash:     []byte{},
		Value:    value,
		PrevHash: prevHash,
	}

	buf, err := newBlock.Marshal()
	if err != nil {
		// TODO log error
		return
	}
	b.blockStore.Set(storage.LastBlockKey, blockHash)

	hexHash := hex.EncodeToString(blockHash)

	// store using hex encoded hash
	b.blockStore.Set(hexHash, buf)
}
