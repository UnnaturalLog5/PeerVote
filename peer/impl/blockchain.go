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

func (n *node) isInBlockchain(uniqID string) bool {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	lastBlockKey := n.blockStore.Get(storage.LastBlockKey)
	for {
		lastBlockHash := hex.EncodeToString(lastBlockKey)
		if lastBlockHash == storage.LastBlockKey {
			return false
		}

		lastBlockBuf := n.blockStore.Get(lastBlockHash)

		block := types.BlockchainBlock{}
		err := block.Unmarshal(lastBlockBuf)
		if err != nil {
			return false
		}

		if block.Value.UniqID == uniqID {
			return true
		}

		lastBlockKey = block.PrevHash
	}
}

func (n *node) addBlock(newBlock types.BlockchainBlock) error {
	prevHash := n.blockStore.Get(storage.LastBlockKey)
	if prevHash == nil {
		n.blockStore.Set(storage.LastBlockKey, make([]byte, 32))
	}

	lastBlockKey := n.blockStore.Get(storage.LastBlockKey)
	lastBlockHash := hex.EncodeToString(lastBlockKey)
	prevHashHex := hex.EncodeToString(newBlock.PrevHash)

	if n.blockStore.Len()-1 != int(newBlock.Index) {
		return nil
	}

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
	log.Info().Str("peerAddr", n.myAddr).Msgf("in step %v added block with uniqid %v", n.step, newBlock.Value.UniqID)

	// s := fmt.Sprintf("%v, %v, %v\n", n.myAddr, newBlock.Index, newBlock.Value.UniqID)

	// f, err := os.OpenFile("blockchain.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	// if err != nil {
	// 	panic(err)
	// }

	// defer f.Close()

	// if _, err = f.WriteString(s); err != nil {
	// 	panic(err)
	// }

	n.blockStore.Set(hexHash, buf)

	return nil
}
