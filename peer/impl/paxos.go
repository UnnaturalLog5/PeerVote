package impl

import (
	"errors"
	"math/rand"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/types"
)

type paxosInstance struct {
	maxID         uint
	acceptedID    uint
	phase         uint
	acceptedValue *types.PaxosValue

	// for proposer
	Phase1C chan struct{}
	Phase2C chan types.PaxosValue
	// Promise Messages
	// maps from peer -> Promise
	promises map[uint][]types.PaxosPromiseMessage
	// Accept Messages
	// maps from peer -> Accept
	accepts map[uint][]types.PaxosAcceptMessage

	// list of tlc messages (for that step)
	tlcMessages    []types.TLCMessage
	tlcMessageSent bool
}

type MultiPaxos interface {
	HandlePrepare(paxosPrepareMessage types.PaxosPrepareMessage) (types.PaxosPromiseMessage, bool)
	HandlePromise(promise types.PaxosPromiseMessage)
	HandlePropose(propose types.PaxosProposeMessage) (types.PaxosAcceptMessage, bool)
	HandleAccept(accept types.PaxosAcceptMessage)
	PreparePaxos(source string) (types.PaxosPrepareMessage, bool)
	ProposePaxos(filename, metahash string) types.PaxosProposeMessage
	// Blocking. Wait for a notification when a threshold of messages is reached (Promise or Accept)
	WaitForNextPhase(timeout time.Duration) bool
}

func (n *node) getNextID() uint {
	_, paxosInstance := n.getCurrent()

	if paxosInstance.maxID == 0 {
		return n.conf.PaxosID
	}

	return paxosInstance.maxID + n.conf.TotalPeers
}

func (n *node) getPaxosInstance(step uint) *paxosInstance {
	_, ok := n.paxosInstances[step]
	if !ok {
		n.paxosInstances[step] = &paxosInstance{
			Phase2C:     make(chan types.PaxosValue, 2),
			Phase1C:     make(chan struct{}, 2),
			promises:    map[uint][]types.PaxosPromiseMessage{},
			accepts:     map[uint][]types.PaxosAcceptMessage{},
			tlcMessages: make([]types.TLCMessage, 0),
		}
	}

	return n.paxosInstances[step]
}

func (n *node) getCurrent() (uint, *paxosInstance) {
	return n.step, n.getPaxosInstance(n.step)
}

func (n *node) PreparePaxos(source string) types.PaxosPrepareMessage {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	step, paxosInstance := n.getCurrent()

	// maxID := paxosInstance.maxID

	// if maxID != 0 {
	baseTime := rand.Intn(100)
	backOffTime := time.Millisecond * time.Duration(baseTime)
	time.Sleep(backOffTime)
	// }

	paxosInstance.phase = 1

	id := n.getNextID()

	log.Warn().Str("peerAddr", n.myAddr).Msgf("peer %v is proposing a value for step %v, id %v", n.myAddr, n.step, id)

	prepare := types.PaxosPrepareMessage{
		Step:   step,
		ID:     id,
		Source: source,
	}

	return prepare
}

func (n *node) HandlePrepare(prepare types.PaxosPrepareMessage) (types.PaxosPromiseMessage, bool) {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	// ignore Paxos Prepare if it's from a different step
	step, paxosInstance := n.getCurrent()

	if step != prepare.Step {
		return types.PaxosPromiseMessage{}, false
	}

	// ignore if the messages id is smaller or equal
	if prepare.ID <= paxosInstance.maxID {
		return types.PaxosPromiseMessage{}, false
	}

	// update current instance
	paxosInstance.maxID = prepare.ID

	// and make promise message
	promise := types.PaxosPromiseMessage{
		Step: step,
		ID:   prepare.ID,
	}

	// if a value was already accepted, relay it
	if paxosInstance.acceptedValue != nil {
		promise.AcceptedValue = paxosInstance.acceptedValue
		promise.AcceptedID = paxosInstance.acceptedID
	}

	return promise, true
}

func (n *node) HandlePromise(from string, promise types.PaxosPromiseMessage) {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	// ignore Paxos Prepare if it's from a different step
	currentStep, paxosInstance := n.getCurrent()
	if currentStep != promise.Step {
		return
	}

	// ignore if proposer not in phase 1
	if paxosInstance.phase != 1 {
		return
	}

	if promise.AcceptedValue != nil {
		paxosInstance.acceptedValue = promise.AcceptedValue
		paxosInstance.acceptedID = promise.AcceptedID
	}

	id := paxosInstance.maxID
	// store
	paxosInstance.promises[id] = append(paxosInstance.promises[id], promise)

	// threshold reached?
	if uint(len(paxosInstance.promises[id])) >= n.threshold {
		// notify waiter
		log.Warn().Str("peerAddr", n.myAddr).Msgf("threshold of promises reached step %v", n.step)
		paxosInstance.Phase1C <- struct{}{}
	}
}

func (n *node) ProposePaxos(proposeValue types.PaxosValue) types.PaxosProposeMessage {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	step, paxosInstance := n.getCurrent()

	paxosInstance.phase = 2

	var propose *types.PaxosProposeMessage

	highestID := uint(0)
	for _, promise := range paxosInstance.promises[paxosInstance.maxID] {
		if highestID < promise.AcceptedID {
			highestID = promise.AcceptedID

			propose = &types.PaxosProposeMessage{
				Step:  step,
				ID:    promise.ID,
				Value: *promise.AcceptedValue,
			}
		}
	}
	if propose == nil {
		propose = &types.PaxosProposeMessage{
			Step:  step,
			ID:    paxosInstance.maxID,
			Value: proposeValue,
		}
	}

	return *propose
}

func (n *node) HandlePropose(from string, propose types.PaxosProposeMessage) (types.PaxosAcceptMessage, bool) {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	// ignore Paxos Propose if it's from a different step
	step, paxosInstance := n.getCurrent()
	if step != propose.Step {
		return types.PaxosAcceptMessage{}, false
	}

	// ignore if the messages id is different
	if propose.ID != paxosInstance.maxID {
		return types.PaxosAcceptMessage{}, false
	}

	// remember which value we accepted
	paxosInstance.acceptedValue = &propose.Value
	paxosInstance.acceptedID = propose.ID

	paxosAcceptMessage := types.PaxosAcceptMessage{
		Step:  step,
		ID:    propose.ID,
		Value: propose.Value,
	}

	log.Warn().Str("peerAddr", n.myAddr).Msgf("accepting proposal id %v", paxosInstance.acceptedID)
	return paxosAcceptMessage, true
}

func (n *node) HandleAccept(from string, accept types.PaxosAcceptMessage) {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	// ignore Paxos Accept if it's from a different step
	step, paxosInstance := n.getCurrent()

	if step != accept.Step {
		return
	}

	if accept.ID != paxosInstance.maxID {
		return
	}

	// store
	paxosInstance.accepts[accept.ID] = append(paxosInstance.accepts[accept.ID], accept)

	id := paxosInstance.maxID
	countByUniqID := map[string]uint{}
	// group by uniqID
	for _, accept := range paxosInstance.accepts[id] {
		value := accept.Value
		countByUniqID[value.UniqID]++
	}

	// check if threshold is reached for any proposed value
	for uniqID, count := range countByUniqID {
		if count >= n.threshold {
			// the waiter can read this value after being notified

			// check for which uniqid the threshold was reached
			for _, accept := range paxosInstance.accepts[id] {
				if uniqID == accept.Value.UniqID {
					value := accept.Value
					paxosInstance.acceptedValue = &value
					break
				}
			}

			value := *paxosInstance.acceptedValue

			log.Warn().Str("peerAddr", n.myAddr).Msgf("threshold of accepts reached for step %v", n.step)

			if !paxosInstance.tlcMessageSent {
				block := n.mintBlock(value)
				go n.sendTLCMessage(step, block)

				paxosInstance.tlcMessageSent = true
			}
		}
	}
}

func (n *node) HandleTLC(from string, TLCMessage types.TLCMessage) error {
	log.Warn().Str("peerAddr", n.myAddr).Msgf("handling TLC from %v, id %v", from, TLCMessage.Block.Value.UniqID)
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	currentStep, _ := n.getCurrent()

	// ignore if the TLCMessage is "outdated"
	if TLCMessage.Step < currentStep {
		return nil
	}

	msgPaxosInstance := n.getPaxosInstance(TLCMessage.Step)
	msgPaxosInstance.tlcMessages = append(msgPaxosInstance.tlcMessages, TLCMessage)

	// check all steps from current if threshold of TLCMessages is reached (catch up)
	step := currentStep
	for {
		paxosInstance := n.getPaxosInstance(step)

		if uint(len(paxosInstance.tlcMessages)) < n.threshold {
			// only keep catching up as long as all the previous instances have reached their threshold
			return nil
		}

		log.Info().Str("peerAddr", n.myAddr).Msgf("threshold of TLC messages for step %v", step)
		block := paxosInstance.tlcMessages[0].Block

		blockHash := block.Hash
		for _, m := range paxosInstance.tlcMessages {
			if string(m.Block.Hash) != string(blockHash) {
				log.Info().Str("peerAddr", n.myAddr).Msgf("threshold of TLC messages for step %v", step)
			}
		}

		err := n.addBlock(block)
		if err != nil {
			return err
		}

		// free memory
		delete(n.paxosInstances, step)

		// advance TLC
		n.step = step + 1

		log.Info().Str("peerAddr", n.myAddr).Msgf("advanced to step %v", n.step)

		n.namingStore.Set(block.Value.Filename, []byte(block.Value.Metahash))

		// send tlc message only for current step
		if step == currentStep {
			if !paxosInstance.tlcMessageSent {
				go n.sendTLCMessage(step, block)
				paxosInstance.tlcMessageSent = true
			}

			log.Info().Str("peerAddr", n.myAddr).Msgf("notify initiating goroutine")
			paxosInstance.Phase2C <- block.Value
			close(paxosInstance.Phase2C)
		}

		step++
	}
}

func (n *node) WaitForPromises(timeout time.Duration) bool {
	n.paxosLock.RLock()
	_, paxosInstance := n.getCurrent()
	C := paxosInstance.Phase1C
	n.paxosLock.RUnlock()

	for {
		select {
		case <-time.After(timeout):
			log.Info().Str("peerAddr", n.myAddr).Msgf("wait timeout")
			// retry
			return false
		case <-C:
			return true
		}
	}
}

func (n *node) WaitForAccepts(timeout time.Duration) (types.PaxosValue, bool) {
	n.paxosLock.RLock()
	_, paxosInstance := n.getCurrent()
	C := paxosInstance.Phase2C
	n.paxosLock.RUnlock()

	for {
		select {
		case <-time.After(timeout):
			log.Info().Str("peerAddr", n.myAddr).Msgf("wait timeout")
			return types.PaxosValue{}, false
		case acceptedValue := <-C:
			return acceptedValue, true
		}
	}
}

func (n *node) findPaxosConsensus(filename, metahash string) bool {
	proposeValue := types.PaxosValue{
		Filename: filename,
		Metahash: metahash,
		UniqID:   xid.New().String(),
	}
	log.Warn().Str("peerAddr", n.myAddr).Msgf("proposing uniqid %v step %v", proposeValue.UniqID, n.step)

	for {
		// Phase 1
	phase1:
		for {
			// initialize round, wait for a new step
			prepare := n.PreparePaxos(n.myAddr)
			// send prepare
			err := n.sendPaxosPrepareMessage(prepare)
			if err != nil {
				continue
			}

			// wait for promises
			// HandlePromise will notify this waiter
			nextPhase := n.WaitForPromises(n.conf.PaxosProposerRetry)
			if nextPhase {
				break phase1
			}
			log.Info().Str("peerAddr", n.myAddr).Msgf("step %v not enough promises - restarting paxos prepare!", n.step)
			// retry after timeout if not successful
		}

		// Phase 2
		propose := n.ProposePaxos(proposeValue)

		err := n.sendPaxosProposeMessage(propose)
		if err != nil {
			continue
		}

		// wait for accepts
		// HandleAccept will notify this waiter
		n.WaitForAccepts(n.conf.PaxosProposerRetry)
		if n.isInBlockchain(proposeValue.UniqID) {
			return true
		}

		log.Err(errors.New("didn't find consensus on my value")).
			Str("peerAddr", n.myAddr).Msgf("step %v value %v", n.step, proposeValue.UniqID)
	}
}
