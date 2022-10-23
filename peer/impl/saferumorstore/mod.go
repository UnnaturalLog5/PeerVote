package saferumorstore

import (
	"sync"

	"go.dedis.ch/cs438/types"
)

type SafeRumorStore interface {
	Get(peer string, from uint) []types.Rumor
	Store(peer string, rumor types.Rumor)
}

type store map[string][]types.Rumor

type safeRumorStore struct {
	sync.RWMutex
	store store
}

func New() SafeRumorStore {
	return &safeRumorStore{
		store: make(store),
	}
}

// Get implements SafeRumorStore
func (s *safeRumorStore) Get(peer string, from uint) []types.Rumor {
	s.RLock()
	defer s.RUnlock()

	return s.store[peer][from:]
}

// IncrementRumor implements SafeRumorStore
func (s *safeRumorStore) Store(peer string, rumor types.Rumor) {
	s.Lock()
	defer s.Unlock()

	if s.store[peer] == nil {
		s.store[peer] = make([]types.Rumor, 0)
	}

	s.store[peer] = append(s.store[peer], rumor)
}
