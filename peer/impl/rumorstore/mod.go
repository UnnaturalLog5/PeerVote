package rumorstore

import (
	"errors"
	"sync"

	"go.dedis.ch/cs438/types"
)

type RumorStore interface {
	// Retrieve all rumors for peer starting at from-value
	// beware the list is zero indexed, rumor sequences are not
	GetRumors(peer string, from uint) []types.Rumor

	GetSequence(peer string) uint

	// Store only works if the rumor is expected, otherwise an error is passed
	Store(rumor types.Rumor) error

	MakeStatusMessage() types.StatusMessage
}

type store map[string][]types.Rumor

type rumorStore struct {
	sync.RWMutex
	store store
}

func New() RumorStore {
	return &rumorStore{
		store: make(store),
	}
}

// Get implements RumorStore
func (r *rumorStore) GetRumors(peer string, from uint) []types.Rumor {
	r.RLock()
	defer r.RUnlock()

	return r.store[peer][from:]
}

// Get implements RumorStore
func (r *rumorStore) GetSequence(peer string) uint {
	r.RLock()
	defer r.RUnlock()

	return uint(len(r.store[peer]))
}

// IncrementRumor implements RumorStore
func (r *rumorStore) Store(rumor types.Rumor) error {
	r.Lock()
	defer r.Unlock()

	peer := rumor.Origin

	// if no entry exists for this peer
	if r.store[peer] == nil {
		r.store[peer] = make([]types.Rumor, 0)
	}

	// only append if matches length + 1
	// make sure there are no "gaps"
	if rumor.Sequence == uint(len(r.store[peer])+1) {
		r.store[peer] = append(r.store[peer], rumor)
	} else {
		return errors.New("the rumor is out of order and cannot be stored")
	}

	return nil
}

func (r *rumorStore) MakeStatusMessage() types.StatusMessage {
	r.RLock()
	defer r.RUnlock()

	statusMessage := make(types.StatusMessage)

	for peer, rumors := range r.store {
		statusMessage[peer] = uint(len(rumors))
	}

	return statusMessage
}
