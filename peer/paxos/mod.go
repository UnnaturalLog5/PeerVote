package paxos

import (
	"sync"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
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

	C chan struct{}

	proposedValue *types.PaxosValue

	// Promise Messages
	// maps from peer -> Promise
	promises []types.PaxosPromiseMessage

	// Accept Messages
	// maps from uniqID -> Accept
	accepts map[string][]types.PaxosAcceptMessage
}

func NewMultiPaxos(totalPeers, paxosID uint, paxosThreshold func(uint) int, paxosProposerRetry time.Duration) MultiPaxos {
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
	HandlePromise(promise types.PaxosPromiseMessage)
	HandlePropose(propose types.PaxosProposeMessage) (types.PaxosAcceptMessage, bool)
	HandleAccept(accept types.PaxosAcceptMessage)
	PreparePaxos(source string) (types.PaxosPrepareMessage, bool)
	ProposePaxos(filename, metahash string) types.PaxosProposeMessage
	WaitForNextPhase(timeout time.Duration) bool
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

func (mp *multiPaxos) getNextID() uint {
	_, paxosInstance := mp.getCurrent()

	if paxosInstance.maxID == 0 {
		return mp.paxosID
	}

	return paxosInstance.maxID + mp.totalPeers
}

func (mp *multiPaxos) getCurrent() (uint, *paxosInstance) {
	step := mp.tlc.step
	_, ok := mp.paxosInstances[step]
	if !ok {
		mp.paxosInstances[step] = &paxosInstance{
			C:        make(chan struct{}),
			promises: []types.PaxosPromiseMessage{},
			accepts:  map[string][]types.PaxosAcceptMessage{},
		}
	}

	return step, mp.paxosInstances[step]
}

func (mp *multiPaxos) WaitForNextPhase(timeout time.Duration) bool {
	mp.RLock()
	_, paxosInstance := mp.getCurrent()
	C := paxosInstance.C
	mp.RUnlock()

	for {
		select {
		case <-time.After(timeout):
			log.Info().Msgf("wait timeout")
			// retry
			return false
		case <-C:
			// move paxos on to next round
			return true
		}
	}
}

func (mp *multiPaxos) PreparePaxos(source string) (types.PaxosPrepareMessage, bool) {
	mp.Lock()
	defer mp.Unlock()

	step, paxosInstance := mp.getCurrent()

	// (to our knowledge) paxos is already going on
	// when the max id is not zero
	if paxosInstance.maxID != 0 {
		return types.PaxosPrepareMessage{}, false
	}

	id := mp.getNextID()

	prepare := types.PaxosPrepareMessage{
		Step:   step,
		ID:     id,
		Source: source,
	}

	return prepare, true
}

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

func (mp *multiPaxos) HandlePromise(promise types.PaxosPromiseMessage) {
	mp.Lock()
	defer mp.Unlock()

	// ignore Paxos Prepare if it's from a different step
	currentStep, paxosInstance := mp.getCurrent()
	if currentStep != promise.Step {
		return
	}

	// ignore if proposer not in phase 1
	if paxosInstance.phase != 1 {
		return
	}

	paxosInstance.promises = append(paxosInstance.promises, promise)

	// threshold reached?
	if len(paxosInstance.promises) >= mp.threshold {
		// notify waiter
		log.Info().Msgf("threshold of promises reached")
		paxosInstance.C <- struct{}{}
	}

	return
}

func (mp *multiPaxos) ProposePaxos(filename, metahash string) types.PaxosProposeMessage {
	id := xid.New().String()
	value := types.PaxosValue{
		UniqID:   id,
		Metahash: metahash,
		Filename: filename,
	}

	mp.Lock()
	defer mp.Unlock()

	step, paxosInstance := mp.getCurrent()

	paxosInstance.proposedValue = &value

	propose := types.PaxosProposeMessage{
		Step:  step,
		ID:    paxosInstance.maxID,
		Value: value,
	}

	return propose
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

	// make sure this list exists
	uniqID := accept.Value.UniqID
	_, ok := paxosInstance.accepts[uniqID]
	if !ok {
		paxosInstance.accepts[uniqID] = []types.PaxosAcceptMessage{}
	}

	// store
	paxosInstance.accepts[uniqID] = append(paxosInstance.accepts[uniqID], accept)

	// check if threshold is reached for any

	for _, accepts := range paxosInstance.accepts {
		if len(accepts) >= mp.threshold {
			// notify waiter
			paxosInstance.C <- struct{}{}
		}
	}

	return
}
