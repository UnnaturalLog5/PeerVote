package electionstore

import (
	"sync"

	"go.dedis.ch/cs438/types"
)

// copied and adapted from store.Store

// Store describes the primitives of a simple storage.
type ElectionStore interface {
	// Get returns nil if not found
	Get(key string) types.Election

	Set(key string, val types.Election)

	StoreVote(key, encryptedChoice string)

	Delete(key string)

	Exists(key string) bool

	Len() int

	GetAll() []types.Election

	// Calls the function on each key/value pair. Aborts if the function returns
	// false.
	ForEach(func(key string, val types.Election) bool)
}

// Storage implements an in-memory storage.
func New() ElectionStore {
	return &store{
		data: make(map[string]types.Election),
	}
}

// store implements an in-memory store.
type store struct {
	sync.Mutex
	data map[string]types.Election
}

// Get implements storage.Store
func (s *store) Get(key string) types.Election {
	s.Lock()
	defer s.Unlock()

	return s.data[key]
}

// Get implements storage.Store
func (s *store) Exists(key string) bool {
	s.Lock()
	defer s.Unlock()

	_, ok := s.data[key]
	return ok
}

// Get implements storage.Store
func (s *store) GetAll() []types.Election {
	s.Lock()
	defer s.Unlock()

	elections := make([]types.Election, 0)

	for _, election := range s.data {
		elections = append(elections, election)
	}

	return elections
}

// Set implements storage.Store
func (s *store) Set(key string, val types.Election) {
	s.Lock()
	defer s.Unlock()

	s.data[string(key)] = val
}

func (s *store) StoreVote(key, vote string) {
	s.Lock()
	defer s.Unlock()

	election := s.data[key]

	election.Votes = append(election.Votes, vote)

	s.data[key] = election
}

// Delete implements storage.Store
func (s *store) Delete(key string) {
	s.Lock()
	defer s.Unlock()

	delete(s.data, string(key))
}

// ForEach implements storage.Store
func (s *store) ForEach(f func(key string, val types.Election) bool) {
	s.Lock()
	defer s.Unlock()

	for k, v := range s.data {
		cont := f(k, v)
		if !cont {
			return
		}
	}
}

// Len implements storage.Store
func (s *store) Len() int {
	s.Lock()
	defer s.Unlock()

	return len(s.data)
}
