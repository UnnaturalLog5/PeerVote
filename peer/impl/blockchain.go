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

	// if it's not the first block, check that the previous hash fits
	if lastBlockHash != prevHashHex {
		return errors.New("the block doesn't match")
	}

	buf, err := newBlock.Marshal()
	if err != nil {
		return err
	}

	// update last block key so we can find the chain's head
	n.blockStore.Set(storage.LastBlockKey, newBlock.Hash)

	// store using hex encoded hash
	hexHash := hex.EncodeToString(newBlock.Hash)
	log.Info().Str("peerAddr", n.myAddr).Msgf("in step %v added block with hash %v", n.step, hexHash)
	n.blockStore.Set(hexHash, buf)

	// TODO remove
	n.GetAllBlocks()

	return nil
}

func (n *node) GetAllBlocks() {
	n.blocks = map[uint]types.BlockchainBlock{}

	lastBlockKey := n.blockStore.Get(storage.LastBlockKey)
	for i := uint(n.blockStore.Len() - 2); ; i-- {
		lastBlockHash := hex.EncodeToString(lastBlockKey)
		// prevHashHex := hex.EncodeToString(newBlock.PrevHash)
		if lastBlockHash == storage.LastBlockKey {
			return
		}

		lastBlockBuf := n.blockStore.Get(lastBlockHash)

		block := types.BlockchainBlock{}
		block.Unmarshal(lastBlockBuf)

		n.blocks[i] = block

		lastBlockKey = block.PrevHash
	}
}
