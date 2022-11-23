package impl

import (
	"math"
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
	C chan types.PaxosValue
	// Promise Messages
	// maps from peer -> Promise
	promises []types.PaxosPromiseMessage
	// Accept Messages
	// maps from uniqID -> Accept
	accepts map[string][]types.PaxosAcceptMessage

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
			C:           make(chan types.PaxosValue, 5),
			promises:    []types.PaxosPromiseMessage{},
			accepts:     map[string][]types.PaxosAcceptMessage{},
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

	maxID := paxosInstance.maxID
	phase := paxosInstance.phase

	for i := 0; maxID != 0 && phase == 0; i++ {
		backOffTime := time.Millisecond * time.Duration(math.Pow(1.2, float64(i)))
		n.paxosLock.Unlock()

		time.Sleep(backOffTime)

		n.paxosLock.Lock()
		step, paxosInstance = n.getCurrent()
		maxID = paxosInstance.maxID
	}

	log.Warn().Str("peerAddr", n.myAddr).Msgf("peer %v is proposing a value for step %v", n.myAddr, n.step)

	paxosInstance.phase = 1

	id := n.getNextID()

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

	paxosInstance.phase = 1

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

func (n *node) HandlePromise(promise types.PaxosPromiseMessage) {
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

	if promise.AcceptedValue != nil && promise.AcceptedID > paxosInstance.acceptedID {
		paxosInstance.acceptedValue = promise.AcceptedValue
		paxosInstance.maxID = paxosInstance.acceptedID
	}

	paxosInstance.promises = append(paxosInstance.promises, promise)

	// threshold reached?
	if len(paxosInstance.promises) >= n.threshold {
		// notify waiter
		log.Warn().Str("peerAddr", n.myAddr).Msgf("threshold of promises reached step %v", n.step)
		paxosInstance.C <- types.PaxosValue{}
	}
}

func (n *node) ProposePaxos(filename, metahash string) types.PaxosProposeMessage {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	step, paxosInstance := n.getCurrent()

	paxosInstance.phase = 2

	var value types.PaxosValue

	if paxosInstance.acceptedValue != nil {
		value = *paxosInstance.acceptedValue
	} else {
		value = types.PaxosValue{
			Filename: filename,
			Metahash: metahash,
			UniqID:   xid.New().String(),
		}
	}

	propose := types.PaxosProposeMessage{
		Step:  step,
		ID:    paxosInstance.maxID,
		Value: value,
	}

	return propose
}

func (n *node) HandlePropose(propose types.PaxosProposeMessage) (types.PaxosAcceptMessage, bool) {
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

	paxosInstance.phase = 2

	// remember which value we accepted
	paxosInstance.acceptedValue = &propose.Value
	paxosInstance.acceptedID = propose.ID

	paxosAcceptMessage := types.PaxosAcceptMessage(propose)

	return paxosAcceptMessage, true
}

func (n *node) HandleAccept(accept types.PaxosAcceptMessage) {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	// ignore Paxos Accept if it's from a different step
	step, paxosInstance := n.getCurrent()

	if step != accept.Step {
		return
	}

	// store
	uniqID := accept.Value.UniqID
	paxosInstance.accepts[uniqID] = append(paxosInstance.accepts[uniqID], accept)

	// check if threshold is reached for any proposed value
	for _, accepts := range paxosInstance.accepts {
		if len(accepts) >= n.threshold {
			// the waiter can read this value after being notified
			paxosInstance.acceptedValue = &accepts[0].Value

			// send TLC Message
			// add block
			value := *paxosInstance.acceptedValue

			log.Info().Str("peerAddr", n.myAddr).Msgf("threshold of accepts reached for step %v", n.step)

			block := n.mintBlock(value)

			if !paxosInstance.tlcMessageSent {
				go n.sendTLCMessage(step, block)

				paxosInstance.tlcMessageSent = true
			}
		}
	}
}

func (n *node) HandleTLC(TLCMessage types.TLCMessage) error {
	n.paxosLock.Lock()
	defer n.paxosLock.Unlock()

	currentStep, _ := n.getCurrent()

	// ignore if the TLCMessage is "outdated"
	if TLCMessage.Step < currentStep {
		return nil
	}

	// store
	log.Info().Str("peerAddr", n.myAddr).Msgf("TLC message from step %v", TLCMessage.Step)

	msgPaxosInstance := n.getPaxosInstance(TLCMessage.Step)
	msgPaxosInstance.tlcMessages = append(msgPaxosInstance.tlcMessages, TLCMessage)

	if n.myAddr == "127.0.0.1:3" {
		log.Info().Str("peerAddr", n.myAddr).Msgf("TLC message from step %v", TLCMessage.Step)
	}

	// check all steps from current if threshold of TLCMessages is reached (catch up)
	step := currentStep
	for {
		paxosInstance := n.getPaxosInstance(step)

		if len(paxosInstance.tlcMessages) < n.threshold {
			// only keep catching up as long as all the previous instances have reached their threshold
			return nil
		}

		log.Info().Str("peerAddr", n.myAddr).Msgf("threshold of TLC messages for step %v", step)
		block := paxosInstance.tlcMessages[0].Block

		err := n.addBlock(block)
		if err != nil {
			return err
		}

		n.step = step + 1

		// advance TLC
		log.Info().Str("peerAddr", n.myAddr).Msgf("advanced to step %v", n.step)

		n.namingStore.Set(block.Value.Filename, []byte(block.Value.Metahash))

		// send tlc message only for current step
		if step == currentStep {
			if !paxosInstance.tlcMessageSent {
				go n.sendTLCMessage(step, block)
				paxosInstance.tlcMessageSent = true
			}

			log.Info().Str("peerAddr", n.myAddr).Msgf("notify initiating goroutine")
			paxosInstance.C <- block.Value

		}

		step++
	}
}

func (n *node) WaitForNextPhase(timeout time.Duration) (types.PaxosValue, bool) {
	n.paxosLock.RLock()
	_, paxosInstance := n.getCurrent()
	C := paxosInstance.C
	n.paxosLock.RUnlock()

	for {
		select {
		case <-time.After(timeout):
			log.Info().Str("peerAddr", n.myAddr).Msgf("wait timeout")
			// retry
			return types.PaxosValue{}, false
		case acceptedValue := <-C:
			return acceptedValue, true
		}
	}
}

func (n *node) findPaxosConsensus(filename, metahash string) bool {
	for {
		// Phase 1
	Phase1:
		for {
			// initialize round, wait for a new step
			prepare := n.PreparePaxos(n.myAddr)
			// log.Info().Str("peerAddr", n.myAddr).Msgf("id: %v", prepare.ID)
			// send prepare
			err := n.sendPaxosPrepareMessage(prepare)
			if err != nil {
				continue
			}

			// wait for promises
			// HandlePromise will notify this waiter
			_, nextPhase := n.WaitForNextPhase(n.conf.PaxosProposerRetry)
			if nextPhase {
				break Phase1
			}
			log.Info().Str("peerAddr", n.myAddr).Msgf("step %v not enough promises - restarting paxos prepare!", n.step)
			// retry after timeout if not successful
		}

		// Phase 2
		propose := n.ProposePaxos(filename, metahash)

		err := n.sendPaxosProposeMessage(propose)
		if err != nil {
			continue
		}

		// wait for accepts
		// HandleAccept will notify this waiter
		acceptedValue, consensus := n.WaitForNextPhase(n.conf.PaxosProposerRetry)
		if consensus && acceptedValue.Filename == filename && acceptedValue.Metahash == metahash {
			return true
		}
	}
}
