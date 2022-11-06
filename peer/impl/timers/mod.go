package timers

import (
	"sync"
	"time"
)

type Timers interface {
	Set(key string, timout time.Duration)

	// waits until the time expires
	Wait(key string)

	// stops timer
	Stop(key string) bool
}

type timers struct {
	sync.RWMutex
	timers map[string]*time.Timer
}

func New() Timers {
	return &timers{
		timers: make(map[string]*time.Timer),
	}
}

func (a *timers) Set(key string, timeout time.Duration) {
	a.Lock()
	defer a.Unlock()

	a.timers[key] = time.NewTimer(timeout)
}

func (a *timers) Wait(key string) {
	a.RLock()
	timer := a.timers[key]
	a.RUnlock()

	<-timer.C
}

func (a *timers) Stop(key string) bool {
	a.Lock()
	defer a.Unlock()

	timer := a.timers[key]
	delete(a.timers, key)

	if timer != nil {
		return timer.Stop()
	}

	return false
}
