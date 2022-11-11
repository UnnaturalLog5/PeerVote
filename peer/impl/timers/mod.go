package timers

import (
	"sync"
	"time"

	"github.com/rs/xid"
)

type Timers interface {
	//
	SetUpMultiple(timeout time.Duration) string

	Register(metaSearchKey, key string)

	// waits until the time expires or it is stopped
	// this operation is blocking
	// returns data, true if the timer was stopped
	//
	// returns nil, false if the timer expired
	//
	// optionally receives data sent by stop function
	WaitMultiple(key string) []any

	WaitSingle(key string, timeout time.Duration) (any, bool)

	// stops timer
	// optionally send data to waiting goroutine
	// pass nil, to not send anything
	Ping(key string, data ...any) bool
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

func New() Timers {
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

func (t *timers) Ping(key string, data ...any) bool {
	t.Lock()
	timerData, ok := t.timers[key]
	if !ok {
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
