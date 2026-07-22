package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"skudkey/src/telegram"
)

var authFailRe = regexp.MustCompile(`AC-AUTH-FAIL:\s*(\{.*\})`)

const dedupWindow = 60 * time.Second

// It does not work with too small hostory window
// Likely because their server has the wrong date
const minHistoryWindow = time.Hour * 24

type Logger interface {
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

type Poller interface {
	GetUpdates(ctx context.Context, offset, timeoutSec int) ([]telegram.Update, error)
}

type Registrar interface {
	CreateKey(ctx context.Context, key string) error
	SetToken(token string)
	KeyName() string
	SetKeyName(name string)
	MaskedToken() string
	CanLogin() bool
	Login(ctx context.Context) error
	ListKeys(ctx context.Context) ([]string, error)
}

type (
	authError  interface{ IsAuthError() bool }
	tokenError interface{ IsTokenExpired() bool }
)

type Options struct {
	ChatID  int64
	UnionID string
	OnKey   func(KeyEvent)
}

const (
	KeyRegistered = "registered"
	KeySkipped    = "skipped"
	KeyFailed     = "failed"
)

type KeyEvent struct {
	Key    string    `json:"key"`
	Name   string    `json:"name"`
	Status string    `json:"status"`
	Detail string    `json:"detail"`
	Time   time.Time `json:"time"`
}

type authFailPayload struct {
	DevType string `json:"dev_type"`
	Key     string `json:"key"`
	KeyHex  string `json:"keyhex"`
	Counter string `json:"counter"`
	Error   string `json:"error"`
	Desc    string `json:"desc"`
}

type App struct {
	log  Logger
	skud Registrar
	opts Options

	mu           sync.Mutex
	paused       bool
	processed    int
	lastErr      string
	dedup        map[string]time.Time
	seenEvents   map[string]time.Time
	existingKeys map[string]bool
	startTime    time.Time
}

func New(log Logger, skud Registrar, opts Options) *App {
	return &App{
		log:          log,
		skud:         skud,
		opts:         opts,
		dedup:        make(map[string]time.Time),
		seenEvents:   make(map[string]time.Time),
		existingKeys: make(map[string]bool),
		startTime:    time.Now(),
	}
}

func (a *App) LoadExistingKeys(ctx context.Context) error {
	keys, err := a.skud.ListKeys(ctx)
	if err != nil {
		return err
	}

	a.mu.Lock()
	for _, k := range keys {
		a.existingKeys[k] = true
	}
	a.mu.Unlock()

	a.log.Info("loaded %d existing key(s) from the SKUD union", len(keys))
	return nil
}

// One log from the logger
type HistoryEvent struct {
	ID      string
	Topic   string
	Payload string
	Time    int64
}

type HistoryFetcher func(ctx context.Context, start, end int64) ([]HistoryEvent, error)

type HistoryOptions struct {
	Interval        time.Duration
	Lookback        time.Duration
	ProcessExisting bool
}

func (a *App) RunHistory(ctx context.Context, fetch HistoryFetcher, opts HistoryOptions) {
	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	first := true
	for {
		if ctx.Err() != nil {
			return
		}

		if a.isPaused() {
			a.log.Info("paused - skipping this history poll")
		} else {
			end := time.Now()
			window := max(opts.Lookback, minHistoryWindow)
			events, err := fetch(ctx, end.Add(-window).Unix(), end.Unix())
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				a.setLastErr(err.Error())
				if a.isTokenExpired(err) && a.skud.CanLogin() {
					a.log.Warn("history request rejected as expired - refreshing the token")
					if lerr := a.skud.Login(ctx); lerr != nil {
						a.log.Error("automatic SKUD login failed: %v", lerr)
					} else {
						a.log.Info("SKUD token refreshed (now %s)", a.skud.MaskedToken())
					}
				} else {
					a.log.Error("history poll failed: %v", err)
				}
			} else {
				a.processHistory(ctx, events, first, opts.ProcessExisting)
				first = false
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) processHistory(ctx context.Context, events []HistoryEvent, first, processExisting bool) {
	baseline := first && !processExisting
	seen := 0

	for _, e := range slices.Backward(events) {

		if !strings.HasSuffix(e.Topic, "AC-AUTH-FAIL") {
			continue
		}
		if !a.claimEvent(e.ID) {
			continue
		}
		seen++
		if baseline {
			continue
		}
		if err := a.handlePayload(ctx, e.Payload); err != nil {
			a.releaseEvent(e.ID)
		}
	}

	if baseline {
		a.log.Info("first poll: %d existing AC-AUTH-FAIL event(s) marked as seen and skipped", seen)
		a.log.Info("only keys tapped from now on will be registered (use --process-existing to change that)")
	}
}

func (a *App) RunPolling(ctx context.Context, poller Poller) {
	const pollTimeout = 30
	offset := 0
	backoff := time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		updates, err := poller.GetUpdates(ctx, offset, pollTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ae authError
			if errors.As(err, &ae) && ae.IsAuthError() {
				a.log.Error("Telegram token rejected mid-run (401) - it may have been revoked. Stopping.")
				a.setLastErr(err.Error())
				return
			}
			a.setLastErr(err.Error())
			a.log.Error("polling failed: %v (retrying in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second

		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			a.handleUpdate(ctx, u)
		}
	}
}

func (a *App) handleUpdate(ctx context.Context, u telegram.Update) {
	msg := u.Message
	if msg == nil {
		msg = u.ChannelPost
	}
	if msg == nil {
		return
	}
	a.HandleMessage(ctx, msg.Chat.ID, msg.Text)
}

func (a *App) HandleMessage(ctx context.Context, chatID int64, text string) {
	if chatID != a.opts.ChatID || text == "" {
		return
	}

	m := authFailRe.FindStringSubmatch(text)
	if m == nil {
		return
	}
	if a.isPaused() {
		a.log.Info("paused - ignoring an AC-AUTH-FAIL event")
		return
	}
	a.handlePayload(ctx, m[1])
}

func (a *App) handlePayload(ctx context.Context, raw string) error {
	var p authFailPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		a.log.Warn("saw AC-AUTH-FAIL but its JSON could not be parsed: %v", err)
		a.setLastErr("malformed AC-AUTH-FAIL payload: " + err.Error())
		return nil
	}
	if p.Error != "" {
		a.log.Info("ignoring AC-AUTH-FAIL for key %q: error field set (%q)", p.Key, p.Error)
		return nil
	}
	if p.Key == "" {
		a.log.Warn("ignoring AC-AUTH-FAIL: empty key")
		return nil
	}

	return a.register(ctx, p)
}

func (a *App) emitKey(key, status, detail string) {
	if a.opts.OnKey == nil {
		return
	}
	a.opts.OnKey(KeyEvent{
		Key:    key,
		Name:   a.skud.KeyName(),
		Status: status,
		Detail: detail,
		Time:   time.Now(),
	})
}

func (a *App) register(ctx context.Context, p authFailPayload) error {
	if a.hasExistingKey(p.Key) {
		a.log.Warn("key %q is already registered on the SKUD union - skipping", p.Key)
		a.emitKey(p.Key, KeySkipped, "already-registered")
		return nil
	}
	if !a.claimKey(p.Key) {
		a.log.Info("skipping key %q - already submitted in the last %s", p.Key, dedupWindow)
		return nil
	}

	a.log.Info("new unregistered key %q (keyhex=%s) - registering as %q", p.Key, p.KeyHex, a.skud.KeyName())

	err := a.skud.CreateKey(ctx, p.Key)
	if a.isTokenExpired(err) && a.skud.CanLogin() {
		a.log.Warn("SKUD token rejected as expired - fetching a fresh one automatically")
		if lerr := a.skud.Login(ctx); lerr != nil {
			a.setLastErr(lerr.Error())
			a.log.Error("automatic SKUD login failed: %v", lerr)
			a.log.Error("hint: check --skud-contract/--skud-password, or set a token with: token <new-jwt>")
			a.releaseKey(p.Key)
			return lerr
		}
		a.log.Info("SKUD token refreshed (now %s) - retrying key %q", a.skud.MaskedToken(), p.Key)
		err = a.skud.CreateKey(ctx, p.Key)
	}

	if err != nil {
		a.releaseKey(p.Key)
		a.reportRegisterError(p.Key, err)
		a.emitKey(p.Key, KeyFailed, err.Error())
		return err
	}

	a.markExisting(p.Key)
	a.incProcessed()
	a.log.Info("key %q registered as %q", p.Key, a.skud.KeyName())
	a.emitKey(p.Key, KeyRegistered, "")
	return nil
}

func (a *App) isTokenExpired(err error) bool {
	var te tokenError
	return errors.As(err, &te) && te.IsTokenExpired()
}

func (a *App) reportRegisterError(key string, err error) {
	a.setLastErr(err.Error())

	if a.isTokenExpired(err) {
		a.log.Error("registering key %q failed: SKUD JWT looks EXPIRED (%v). Refresh it, then run: token <new-jwt>", key, err)
		return
	}

	a.log.Error("registering key %q failed: %v", key, err)
}

func (a *App) HotSwapToken(token string) string {
	a.skud.SetToken(token)
	return a.skud.MaskedToken()
}

func (a *App) SetKeyName(name string) (previous string) {
	previous = a.skud.KeyName()
	a.skud.SetKeyName(name)
	return previous
}

func (a *App) KeyName() string { return a.skud.KeyName() }

func (a *App) Login(ctx context.Context) error {
	if err := a.skud.Login(ctx); err != nil {
		a.setLastErr(err.Error())
		return err
	}
	return nil
}

func (a *App) CanLogin() bool { return a.skud.CanLogin() }

func (a *App) SetPaused(paused bool) (was bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	was, a.paused = a.paused, paused
	return was
}

func (a *App) Status() string {
	a.mu.Lock()
	uptime := time.Since(a.startTime).Round(time.Second)
	state := "running"
	if a.paused {
		state = "paused"
	}
	lastErr := a.lastErr
	processed := a.processed
	a.mu.Unlock()

	if lastErr == "" {
		lastErr = "(none)"
	}
	return fmt.Sprintf(
		"status:\n"+
			"  state          : %s\n"+
			"  uptime         : %s\n"+
			"  chat id        : %d\n"+
			"  union id       : %s\n"+
			"  key name       : %s\n"+
			"  skud jwt       : %s\n"+
			"  keys processed : %d\n"+
			"  last error     : %s",
		state, uptime, a.opts.ChatID, a.opts.UnionID, a.skud.KeyName(),
		a.skud.MaskedToken(), processed, lastErr,
	)
}

func (a *App) Processed() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.processed
}

func (a *App) Paused() bool { return a.isPaused() }

func (a *App) MaskedToken() string { return a.skud.MaskedToken() }

func (a *App) Uptime() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.startTime).Round(time.Second)
}

func (a *App) LastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

func (a *App) claimKey(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if last, ok := a.dedup[key]; ok && now.Sub(last) < dedupWindow {
		return false
	}
	a.dedup[key] = now

	for k, t := range a.dedup {
		if now.Sub(t) >= dedupWindow {
			delete(a.dedup, k)
		}
	}
	return true
}

func (a *App) releaseKey(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.dedup, key)
}

func (a *App) hasExistingKey(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.existingKeys[key]
}

func (a *App) markExisting(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.existingKeys[key] = true
}

const eventTTL = 6 * time.Hour

func (a *App) claimEvent(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	if _, ok := a.seenEvents[id]; ok {
		return false
	}
	a.seenEvents[id] = now

	for k, t := range a.seenEvents {
		if now.Sub(t) >= eventTTL {
			delete(a.seenEvents, k)
		}
	}
	return true
}

func (a *App) releaseEvent(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.seenEvents, id)
}

func (a *App) isPaused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.paused
}

func (a *App) incProcessed() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.processed++
}

func (a *App) setLastErr(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastErr = msg
}
