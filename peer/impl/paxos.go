package impl

import (
	"sync"

	"go.dedis.ch/cs438/types"
)

type TLC struct {
	currentStep     uint
	TLCMessageStore map[uint]types.TLCMessage
}

func getNextID() {

}

func newTLC() TLC {
	MessagesStore := make(map[uint]types.TLCMessage)
	return TLC{
		TLCMessageStore: MessagesStore,
	}
}

func newMultiPaxos() MultiPaxos {
	PaxosInstances := make(map[uint]PaxosInstance)
	TLC := newTLC()
	return MultiPaxos{
		paxosInstances: PaxosInstances,
		tlc:            TLC,
	}
}

type MultiPaxos struct {
	sync.RWMutex
	paxosInstances map[uint]PaxosInstance
	tlc            TLC
}

func (mp *MultiPaxos) getCurrentStep() uint {
	mp.RLock()
	defer mp.RUnlock()

	return mp.tlc.currentStep
}

func (mp *MultiPaxos) getPaxosInstance(step uint) (PaxosInstance, bool) {
	mp.RLock()
	defer mp.RUnlock()

	paxosInstance, ok := mp.paxosInstances[step]
	return paxosInstance, ok
}

func (mp *MultiPaxos) getCurrentPaxosInstance() (PaxosInstance, bool) {
	currentStep := mp.getCurrentStep()
	paxosInstance, ok := mp.getPaxosInstance(currentStep)
	return paxosInstance, ok
}

func (mp *MultiPaxos) updatePaxosInstance(step uint, paxosInstance PaxosInstance) {
	mp.Lock()
	defer mp.Unlock()

	mp.paxosInstances[step] = paxosInstance
}

type PaxosInstance struct {
	MaxID         uint
	AcceptedID    uint
	AcceptedValue *types.PaxosValue
}
