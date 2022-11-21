package impl

import (
	"sync"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/types"
)

type tlc struct {
	step        uint
	tlcMessages map[uint]types.TLCMessage
}

func newTLC() tlc {
	MessagesStore := make(map[uint]types.TLCMessage)
	return tlc{
		tlcMessages: MessagesStore,
	}
}

type paxosInstance struct {
	maxID      uint
	acceptedID uint
	phase      uint

	// for acceptor

	acceptedValue *types.PaxosValue

	// for proposer

	proposedValue *types.PaxosValue

	// Promise Messages
	// maps from peer -> Promise
	promises []types.PaxosPromiseMessage

	// Accept Messages
	// maps from uniqID -> Accept
	accepts map[string][]types.PaxosAcceptMessage
}

func newMultiPaxos(totalPeers, paxosID uint, paxosThreshold func(uint) int, paxosProposerRetry time.Duration) MultiPaxos {
	PaxosInstances := make(map[uint]*paxosInstance)
	tlc := newTLC()
	threshold := paxosThreshold(totalPeers)
	return &multiPaxos{
		paxosInstances:     PaxosInstances,
		tlc:                tlc,
		threshold:          threshold,
		totalPeers:         totalPeers,
		paxosID:            paxosID,
		paxosProposerRetry: paxosProposerRetry,
	}
}

type MultiPaxos interface {
	HandlePrepare(paxosPrepareMessage types.PaxosPrepareMessage) (types.PaxosPromiseMessage, bool)
	HandlePromise(promise types.PaxosPromiseMessage) (types.PaxosProposeMessage, bool)
	HandlePropose(propose types.PaxosProposeMessage) (types.PaxosAcceptMessage, bool)
	HandleAccept(accept types.PaxosAcceptMessage)
	GetNextID() uint
}

type multiPaxos struct {
	sync.RWMutex
	// paxos instances
	paxosInstances map[uint]*paxosInstance
	tlc            tlc

	threshold          int
	totalPeers         uint
	paxosID            uint
	paxosProposerRetry time.Duration
}

func (mp *multiPaxos) GetNextID() uint {
	mp.RLock()
	defer mp.RUnlock()

	_, paxosInstance := mp.getCurrent()
	return paxosInstance.maxID + mp.totalPeers
}

func (mp *multiPaxos) getCurrent() (uint, *paxosInstance) {
	step := mp.tlc.step
	_, ok := mp.paxosInstances[step]
	if !ok {
		mp.paxosInstances[step] = &paxosInstance{}
	}

	return step, mp.paxosInstances[step]
}

// func (mp *multiPaxos) Start

func (mp *multiPaxos) HandlePrepare(prepare types.PaxosPrepareMessage) (types.PaxosPromiseMessage, bool) {
	mp.Lock()
	defer mp.Unlock()

	// ignore Paxos Prepare if it's from a different step
	step, paxosInstance := mp.getCurrent()

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

func (mp *multiPaxos) HandlePromise(promise types.PaxosPromiseMessage) (types.PaxosProposeMessage, bool) {
	mp.Lock()
	defer mp.Unlock()

	// ignore Paxos Prepare if it's from a different step
	currentStep, paxosInstance := mp.getCurrent()
	if currentStep != promise.Step {
		return types.PaxosProposeMessage{}, false
	}

	// ignore if proposer not in phase 1
	if paxosInstance.phase != 1 {
		return types.PaxosProposeMessage{}, false
	}

	if paxosInstance.promises == nil {
		paxosInstance.promises = []types.PaxosPromiseMessage{}
	}

	paxosInstance.promises = append(paxosInstance.promises, promise)

	// threshold reached?
	if len(paxosInstance.promises) > mp.threshold {
		// go to phase 2
		paxosInstance.phase = 2

		paxosProposeMessage := types.PaxosProposeMessage{
			Step:  currentStep,
			ID:    paxosInstance.maxID,
			Value: *paxosInstance.proposedValue,
		}

		// notify originator to stop timeout

		// broadcast propose message
		return paxosProposeMessage, true
	}

	return types.PaxosProposeMessage{}, false
}

func (mp *multiPaxos) HandlePropose(propose types.PaxosProposeMessage) (types.PaxosAcceptMessage, bool) {
	// ignore Paxos Propose if it's from a different step
	step, paxosInstance := mp.getCurrent()
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

	paxosAcceptMessage := types.PaxosAcceptMessage{
		Step:  propose.Step,
		ID:    propose.ID,
		Value: propose.Value,
	}

	return paxosAcceptMessage, true
}

func (mp *multiPaxos) HandleAccept(accept types.PaxosAcceptMessage) {
	// ignore Paxos Accept if it's from a different step
	step, paxosInstance := mp.getCurrent()

	if step != accept.Step {
		// return types.PaxosAcceptMessage{}, false
		return
	}

	if paxosInstance.phase != 2 {
		return
	}

	// make sure map exists
	if paxosInstance.accepts == nil {
		paxosInstance.accepts = map[string][]types.PaxosAcceptMessage{}
	}

	// make sure this list exists
	uniqID := accept.Value.UniqID
	_, ok := paxosInstance.accepts[uniqID]
	if !ok {
		paxosInstance.accepts[uniqID] = []types.PaxosAcceptMessage{}
	}

	// store
	paxosInstance.accepts[uniqID] = append(paxosInstance.accepts[uniqID], accept)

	// check if threshold is reached for anoy

	for _, accepts := range paxosInstance.accepts {
		if len(accepts) > mp.threshold {
			// report back result
			// stop timer
			return
		}
	}

	return
}

func (n *node) findPaxosConsensus(filename, metahash string) bool {
	if n.conf.TotalPeers == 1 {
		return true
	}

	uniqID := xid.New().String()
	value := types.PaxosValue{
		UniqID:   uniqID,
		Filename: filename,
		Metahash: metahash,
	}

	// step, currentPaxosInstance := n.multiPaxos.getCurrent()
	// if currentPaxosInstance.maxID != 0 {
	// paxos already working
	// 	return // error
	// }

	// newPaxosInstance := paxosInstance{
	// 	phase:         1,
	// 	maxID:         n.conf.PaxosID,
	// 	proposedValue: &value,
	// }

	// n.multiPaxos.updatePaxosInstance(step, newPaxosInstance)

	// send prepare
	// wait for promises
	// retry after timer if not successful

	// send propose
	// wait for accepts
	// retry after timeout if not successful

	return true
}
