package acktimers

import (
	"sync"
	"time"
)

type AckTimers interface {
	Set(pktId string, timout time.Duration)

	// waits until the time expires
	Wait(pktId string)

	// stops timer
	Stop(pktId string) bool
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

func (a *ackTimers) Set(pktId string, timeout time.Duration) {
	a.Lock()
	defer a.Unlock()

	a.timers[pktId] = time.NewTimer(timeout)
}

func (a *ackTimers) Wait(pktId string) {
	a.RLock()
	timer := a.timers[pktId]
	a.RUnlock()

	<-timer.C
}

func (a *ackTimers) Stop(pktId string) bool {
	a.Lock()
	defer a.Unlock()

	timer := a.timers[pktId]
	delete(a.timers, pktId)

	if timer != nil {
		return timer.Stop()
	}

	return false
}
