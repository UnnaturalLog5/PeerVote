package asyncnotify

import (
	"sync"
	"time"

	"github.com/rs/xid"
)

// Two types of uses
// 1. WaitSingle(key) for a single notification
//
// 2. WaitMultiple(metaSearchKey) for multiple notifications
// Requires SetUpMultiple(..) to set up the search, generating a metaSearchKey
// use Register(key, ..) to register a notification channel (usually packetID)
//
// Notify() and optionally send data, which is received by the waiter
type AsyncNotify interface {
	// Set up meta search
	SetUpMultiple(timeout time.Duration) string

	// register waiter, use this key to notify and send data
	Register(metaSearchKey, key string)

	// waits until the time expires
	// this operation is blocking
	// optionally receives data sent by Notify()
	WaitMultiple(key string) []any

	// waits until the time expires or it receives the first notification
	// this operation is blocking
	// optionally receives data sent by Notify()
	WaitSingle(key string, timeout time.Duration) (any, bool)

	// notify waiter
	// optionally send data to waiting goroutine
	Notify(key string, data ...any) bool

	Wait(key string, timeout time.Duration) (any, bool)
	RegisterTimer(key string, timeout time.Duration) string
}

type timerData struct {
	c             chan any
	metaSearchKey string
	timeout       time.Duration
}

type timers struct {
	sync.Mutex
	timers map[string]*timerData
}

func New() AsyncNotify {
	return &timers{
		timers: make(map[string]*timerData),
	}
}

func (t *timers) WaitSingle(key string, timeout time.Duration) (any, bool) {
	waitID := t.SetUpMultiple(timeout)
	t.Register(waitID, key)
	return t.Wait(key, timeout)
}

func (t *timers) Wait(key string, timeout time.Duration) (any, bool) {
	t.Lock()
	timerData := t.timers[key]
	t.Unlock()

	select {
	case <-time.After(timeout):
		// timer expired
		return nil, false
	case datum := <-timerData.c:
		return datum, true
	}
}

func (t *timers) SetUpMultiple(timeout time.Duration) string {
	c := make(chan any)
	waitID := xid.New().String()

	timerData := &timerData{
		c:             c,
		metaSearchKey: waitID,
		timeout:       timeout,
	}

	t.Lock()
	t.timers[waitID] = timerData
	t.Unlock()

	// delete traces of search after
	go func() {
		<-time.After(timeout)

		t.Lock()
		delete(t.timers, waitID)
		t.Unlock()
	}()

	return waitID
}

func (t *timers) Register(waitID, key string) {
	t.Lock()
	timerData := t.timers[waitID]
	timeout := timerData.timeout
	t.timers[key] = timerData
	t.Unlock()

	// delete traces of search after
	go func() {
		<-time.After(timeout)

		t.Lock()
		delete(t.timers, key)
		t.Unlock()
	}()
}

func (t *timers) WaitMultiple(waitID string) []any {
	t.Lock()
	timerData := t.timers[waitID]
	timeout := timerData.timeout
	c := timerData.c
	t.Unlock()

	data := make([]any, 0)

	for {
		select {
		case <-time.After(timeout):
			// timer expired
			return data
		case datum := <-c:
			// received data
			data = append(data, datum)
		}
	}
}

func (t *timers) Notify(key string, data ...any) bool {
	t.Lock()
	timerData, ok := t.timers[key]
	if !ok {
		t.Unlock()
		// the timer did not exist
		// it expired or was stopped
		return false
	}

	c := timerData.c
	t.Unlock()

	var sendData any
	if len(data) == 0 {
		// send data via data channel
		sendData = nil
	} else {
		sendData = data[0]
	}
	c <- sendData
	return true
}

func (t *timers) RegisterTimer(key string, timeout time.Duration) string {
	t.Lock()
	defer t.Unlock()
	tim, exists := t.timers[key]
	if exists {
		return tim.metaSearchKey
	}

	c := make(chan any)
	waitID := xid.New().String()

	timerData := &timerData{
		c:             c,
		metaSearchKey: waitID,
		timeout:       timeout,
	}
	t.timers[key] = timerData
	return waitID
}
