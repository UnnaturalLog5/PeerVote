package acktimers

import (
	"sync"
	"time"
)

type AckTimers interface {
	Set(pktID string, timout time.Duration)

	// waits until the time expires
	Wait(pktID string)

	// stops timer
	Stop(pktID string) bool
}

type ackTimers struct {
	sync.RWMutex
	timers map[string]*time.Timer
}

func New() AckTimers {
	timers := make(map[string]*time.Timer)

	return &ackTimers{
		timers: timers,
	}
}

func (a *ackTimers) Set(pktID string, timeout time.Duration) {
	a.Lock()
	defer a.Unlock()

	a.timers[pktID] = time.NewTimer(timeout)
}

func (a *ackTimers) Wait(pktID string) {
	a.RLock()
	timer := a.timers[pktID]
	a.RUnlock()

	<-timer.C
}

func (a *ackTimers) Stop(pktID string) bool {
	a.Lock()
	defer a.Unlock()

	timer := a.timers[pktID]
	delete(a.timers, pktID)

	if timer != nil {
		return timer.Stop()
	}

	return false
}
