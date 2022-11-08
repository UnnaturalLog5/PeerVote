package timers

import (
	"sync"
	"time"
)

type Timers interface {
	// waits until the time expires
	// returns true if the timer was stopped
	//
	// returns false if the timer expired
	//
	// optionally receives data sent by stop function
	Wait(key string, timeout time.Duration) (any, bool)

	// stops timer
	// optionally send data to waiting goroutine
	// pass nil, to not send anything
	Stop(key string, data any) bool
}

type timers struct {
	sync.RWMutex
	timers map[string]chan any
}

func New() Timers {
	return &timers{
		timers: make(map[string]chan any),
	}
}

func (t *timers) Wait(key string, timeout time.Duration) (any, bool) {
	c := make(chan any)
	t.Lock()
	t.timers[key] = c
	t.Unlock()

	defer func() {
		t.Lock()
		delete(t.timers, key)
		t.Unlock()
	}()

	select {
	case <-time.After(timeout):
		return nil, false
	case data := <-c:
		// received data
		// i.e. stopped early
		return data, true
	}
}

func (t *timers) Stop(key string, data any) bool {
	t.RLock()
	c, ok := t.timers[key]
	t.RUnlock()

	if !ok {
		// the timer did not exist
		// it expired or was stopped 
		return false
	}

	// send data via data channel
	c <- data

	return true
}
