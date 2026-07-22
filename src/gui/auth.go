package gui

import (
	"context"
	"errors"
	"sync"
)

type authPrompt struct {
	mu      sync.Mutex
	kind    string // "" | "code" | "password"
	answers chan string
}

func newAuthPrompt() *authPrompt {
	return &authPrompt{}
}

func (a *authPrompt) Code(ctx context.Context) (string, error) {
	return a.ask(ctx, "code")
}

func (a *authPrompt) Password(ctx context.Context) (string, error) {
	return a.ask(ctx, "password")
}

func (a *authPrompt) Pending() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.kind
}

func (a *authPrompt) Submit(value string) error {
	a.mu.Lock()
	ch := a.answers
	a.mu.Unlock()

	if ch == nil {
		return errors.New("nothing is waiting for a login code right now")
	}
	select {
	case ch <- value:
		return nil
	default:
		return errors.New("an answer is already being processed")
	}
}

func (a *authPrompt) ask(ctx context.Context, kind string) (string, error) {
	ch := make(chan string, 1)

	a.mu.Lock()
	a.kind, a.answers = kind, ch
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.kind, a.answers = "", nil
		a.mu.Unlock()
	}()

	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
