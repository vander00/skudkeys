package gui

import (
	"sync"

	"skudkey/src/app"
)

const maxEvents = 500

type KeyLog struct {
	mu     sync.Mutex
	events []app.KeyEvent
	subs   map[chan app.KeyEvent]struct{}
}

func NewKeyLog() *KeyLog {
	return &KeyLog{subs: make(map[chan app.KeyEvent]struct{})}
}

func (k *KeyLog) Add(e app.KeyEvent) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.events = append(k.events, e)
	if len(k.events) > maxEvents {
		k.events = k.events[len(k.events)-maxEvents:]
	}
	for ch := range k.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (k *KeyLog) Events() []app.KeyEvent {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]app.KeyEvent(nil), k.events...)
}

func (k *KeyLog) Subscribe() (<-chan app.KeyEvent, func()) {
	ch := make(chan app.KeyEvent, 256)

	k.mu.Lock()
	k.subs[ch] = struct{}{}
	k.mu.Unlock()

	return ch, func() {
		k.mu.Lock()
		if _, ok := k.subs[ch]; ok {
			delete(k.subs, ch)
			close(ch)
		}
		k.mu.Unlock()
	}
}
