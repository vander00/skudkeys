package runner

import (
	"context"
	"errors"
	"sync"
	"time"

	"skudkey/src/app"
	"skudkey/src/config"
	"skudkey/src/logging"
	"skudkey/src/mtproto"
	"skudkey/src/skud"
	"skudkey/src/telegram"
)

type Runner struct {
	log   *logging.Logger
	onKey func(app.KeyEvent)

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	current *app.App
	cfg     *config.Config
	lastErr string
}

func New(log *logging.Logger, onKey func(app.KeyEvent)) *Runner {
	return &Runner{log: log, onKey: onKey}
}

func (r *Runner) App() *app.App {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current != nil
}

func (r *Runner) Config() *config.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

func (r *Runner) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (r *Runner) setLastErr(msg string) {
	r.mu.Lock()
	r.lastErr = msg
	r.mu.Unlock()
}

func (r *Runner) Start(cfg *config.Config, auth mtproto.Authenticator) error {
	r.mu.Lock()
	if r.current != nil {
		r.mu.Unlock()
		return errors.New("already running")
	}
	r.mu.Unlock()

	if missing := cfg.Missing(); len(missing) > 0 {
		return errors.New("missing settings: " + joinAnd(missing))
	}

	sk := skud.New(skud.Config{
		UnionID:  cfg.SkudUnionID,
		Token:    cfg.SkudJWT,
		KeyName:  cfg.KeyName,
		Contract: cfg.SkudContract,
		Password: cfg.SkudPassword,
	})

	ctx, cancel := context.WithCancel(context.Background())
	application := app.New(r.log, sk, app.Options{
		ChatID:  cfg.ChatID,
		UnionID: cfg.SkudUnionID,
		OnKey:   r.onKey,
	})
	done := make(chan struct{})

	r.mu.Lock()
	r.cancel, r.done, r.current, r.cfg, r.lastErr = cancel, done, application, cfg, ""
	r.mu.Unlock()

	go func() {
		defer close(done)
		defer func() {
			r.mu.Lock()
			r.current, r.cancel, r.done = nil, nil, nil
			r.mu.Unlock()
		}()

		r.ensureToken(ctx, sk, cfg)
		if err := application.LoadExistingKeys(ctx); err != nil {
			r.log.Warn("could not preload existing SKUD keys: %v", err)
		}

		switch cfg.Mode {
		case config.ModeMTProto:
			r.runMTProto(ctx, application, cfg, auth)
		case config.ModeBot:
			r.runBot(ctx, application, cfg)
		default:
			r.runHistory(ctx, application, sk, cfg)
		}

		r.log.Info("stopped - processed %d key(s) this session", application.Processed())
	}()

	return nil
}

func (r *Runner) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (r *Runner) ensureToken(ctx context.Context, sk *skud.Client, cfg *config.Config) {
	if cfg.SkudJWT != "" || !sk.CanLogin() {
		return
	}
	r.log.Info("no SKUD token configured - logging in with contract %q", cfg.SkudContract)
	if err := sk.Login(ctx); err != nil {
		r.setLastErr(err.Error())
		r.log.Error("initial SKUD login failed: %v", err)
		r.log.Error("hint: check the SKUD contract and password in settings")
		return
	}
	r.log.Info("SKUD login successful (token %s)", sk.MaskedToken())
}

func (r *Runner) runHistory(ctx context.Context, application *app.App, sk *skud.Client, cfg *config.Config) {
	fetch := func(ctx context.Context, start, end int64) ([]app.HistoryEvent, error) {
		events, err := sk.History(ctx, cfg.MAC, start, end, 500)
		if err != nil {
			return nil, err
		}
		out := make([]app.HistoryEvent, 0, len(events))
		for _, e := range events {
			if cfg.Debug {
				r.log.Info("history event: %s %s %s", e.Topic, e.Payload, time.Unix(e.Time, 0).Format("15:04:05"))
			}
			out = append(out, app.HistoryEvent{ID: e.UUID, Topic: e.Topic, Payload: e.Payload, Time: e.Time})
		}
		return out, nil
	}

	r.log.Info("polling SKUD history for %s every %s (window %s), registering new keys as %q",
		cfg.MAC, cfg.PollInterval, cfg.Lookback, cfg.KeyName)
	application.RunHistory(ctx, fetch, app.HistoryOptions{
		Interval:        cfg.PollInterval,
		Lookback:        cfg.Lookback,
		ProcessExisting: cfg.ProcessExisting,
	})
}

func (r *Runner) runMTProto(ctx context.Context, application *app.App, cfg *config.Config, auth mtproto.Authenticator) {
	client := mtproto.New(mtproto.Config{
		APIID:       cfg.APIID,
		APIHash:     cfg.APIHash,
		Phone:       cfg.Phone,
		Password:    cfg.Password,
		SessionPath: cfg.SessionPath,
		ChatID:      cfg.ChatID,
		Debug:       cfg.Debug,
		Auth:        auth,
	}, r.log, func(ctx context.Context, chatID int64, text string) {
		application.HandleMessage(ctx, chatID, text)
	})

	r.log.Info("starting in MTProto mode (user account)")
	if err := client.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.setLastErr(err.Error())
		r.log.Error("MTProto client stopped: %v", err)
		r.log.Error("hint: check api_id/api_hash from my.telegram.org and that the phone number is correct.")
	}
}

func (r *Runner) runBot(ctx context.Context, application *app.App, cfg *config.Config) {
	tg := telegram.New(cfg.TelegramToken, cfg.ChatID)

	me, err := tg.GetMe(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		r.setLastErr(err.Error())
		var apiErr *telegram.APIError
		if errors.As(err, &apiErr) {
			r.log.Error("Telegram rejected the bot token: %v", apiErr)
			r.log.Error("hint: check the bot token in settings; recreate it via BotFather if needed.")
			return
		}
		r.log.Error("could not reach the Telegram API: %v", err)
		r.log.Error("hint: check your connection and that api.telegram.org is reachable.")
		return
	}
	r.log.Info("authenticated with Telegram as @%s", me.Username)
	if !me.CanReadAllGroupMessages {
		r.log.Warn("privacy mode looks ENABLED - the bot may not see other members' messages.")
		r.log.Warn("disable it in BotFather: /setprivacy -> pick the bot -> Disable, then re-add it to the group.")
	}
	r.log.Warn("Bot API mode cannot see other bots' group messages unless Bot-to-Bot")
	r.log.Warn("Communication Mode is enabled in BotFather. Use MTProto mode otherwise.")

	if cfg.Debug {
		tg.SetDebug(func(raw string) { r.log.Info("raw update: %s", raw) })
		r.log.Info("debug mode on - every received update will be logged verbatim")
	}

	r.log.Info("watching chat %d for AC-AUTH-FAIL events (new keys registered as %q)", cfg.ChatID, cfg.KeyName)
	application.RunPolling(ctx, tg)
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	out := ""
	for i, s := range items {
		switch {
		case i == 0:
			out = s
		case i == len(items)-1:
			out += " and " + s
		default:
			out += ", " + s
		}
	}
	return out
}
