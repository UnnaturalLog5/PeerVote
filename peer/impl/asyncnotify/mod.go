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
	waitId := xid.New().String()

	timerData := &timerData{
		c:             c,
		metaSearchKey: waitId,
		timeout:       timeout,
	}

	t.Lock()
	t.timers[waitId] = timerData
	t.Unlock()

	// delete traces of search after
	go func() {
		<-time.After(timeout)

		t.Lock()
		delete(t.timers, waitId)
		t.Unlock()
	}()

	return waitId
}

func (t *timers) Register(waitId, key string) {
	t.Lock()
	timerData := t.timers[waitId]
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

func (t *timers) WaitMultiple(waitId string) []any {
	t.Lock()
	timerData := t.timers[waitId]
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