package safesequencestore

import (
	"sync"

	"go.dedis.ch/cs438/types"
)

type SafeSequenceStore interface {
	Get(peer string) uint
	Increment(peer string) uint
	GetStatus() types.StatusMessage
}

type store map[string]uint

type safeSequenceStore struct {
	sync.RWMutex
	store store
}

func New() SafeSequenceStore {
	return &safeSequenceStore{
		store: make(store),
	}
}

// GetSequence implements SafeSequenceStore
func (s *safeSequenceStore) Get(peer string) uint {
	s.RLock()
	defer s.RUnlock()

	return s.store[peer]
}

// IncrementSequence implements SafeSequenceStore
func (s *safeSequenceStore) Increment(peer string) uint {
	s.Lock()
	defer s.Unlock()

	// this works even if peer was previously unknown
	// maps with int values are initialized to 0, thus setting the value to 1
	s.store[peer] += 1
	return s.store[peer]
}

// IncrementSequence implements SafeSequenceStore
func (s *safeSequenceStore) GetStatus() types.StatusMessage {
	s.RLock()
	defer s.RUnlock()

	statusMessage := make(types.StatusMessage)

	for k, v := range s.store {
		statusMessage[k] = v
	}

	return statusMessage
}
