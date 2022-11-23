package impl

import (
	"crypto"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/types"
)

func (n *node) mintBlock(value types.PaxosValue) types.BlockchainBlock {
	prevHash := n.blockStore.Get(storage.LastBlockKey)
	if prevHash == nil {
		n.blockStore.Set(storage.LastBlockKey, make([]byte, 32))
	}
	prevHash = n.blockStore.Get(storage.LastBlockKey)

	newBlock := types.BlockchainBlock{
		Index:    n.step,
		Value:    value,
		PrevHash: prevHash,
	}

	// H = sha256(Index || v.UniqID || v.Filename || v.Metahash || Prevhash)
	hash := crypto.SHA256.New()
	hash.Write([]byte(strconv.Itoa(int(newBlock.Index))))
	hash.Write([]byte(newBlock.Value.UniqID))
	hash.Write([]byte(newBlock.Value.Filename))
	hash.Write([]byte(newBlock.Value.Metahash))
	hash.Write(newBlock.PrevHash)
	blockHash := hash.Sum(nil)

	newBlock.Hash = blockHash

	return newBlock
}

func (n *node) addBlock(newBlock types.BlockchainBlock) error {
	prevHash := n.blockStore.Get(storage.LastBlockKey)
	if prevHash == nil {
		n.blockStore.Set(storage.LastBlockKey, make([]byte, 32))
	}

	lastBlockKey := n.blockStore.Get(storage.LastBlockKey)
	lastBlockHash := hex.EncodeToString(lastBlockKey)
	prevHashHex := hex.EncodeToString(newBlock.PrevHash)

	// lastBlock := n.blockStore.Get((lastBlockHash))
	log.Warn().Str("peerAddr", n.myAddr).Msgf("---adding block with index %v for step %v as the %vth block", newBlock.Index, n.step, n.blockStore.Len())

	// if it's not the first block, check that the previous hash fits
	if lastBlockHash != prevHashHex {
		// TODO
		return errors.New("the same block was already added")
	}

	buf, err := newBlock.Marshal()
	if err != nil {
		return err
	}

	// update last block key so we can find the chain's head
	n.blockStore.Set(storage.LastBlockKey, newBlock.Hash)

	// store using hex encoded hash
	hexHash := hex.EncodeToString(newBlock.Hash)
	n.blockStore.Set(hexHash, buf)

	return nil
}
