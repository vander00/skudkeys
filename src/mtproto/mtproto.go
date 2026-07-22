// Package mtproto reads chat messages through the Telegram client API
// (MTProto) using a real user account. Unlike the Bot API, a user account
// receives messages sent by other bots, which is what this program needs.
package mtproto

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
)

// channelIDOffset converts between MTProto channel ids and the "-100…" ids
// used by the Bot API and by this program's configuration.
const channelIDOffset = -1000000000000

// Logger is the logging surface this package needs.
type Logger interface {
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

// MessageHandler receives every message from the watched chat.
type MessageHandler func(ctx context.Context, chatID int64, text string)

// Authenticator supplies the credentials Telegram asks for interactively during
// login. The GUI implements it by prompting the user in the browser.
type Authenticator interface {
	Code(ctx context.Context) (string, error)
	Password(ctx context.Context) (string, error)
}

// Config holds the MTProto credentials and target chat.
type Config struct {
	APIID       int
	APIHash     string
	Phone       string
	Password    string // 2FA password; empty if 2FA is not enabled
	SessionPath string
	ChatID      int64 // "-100…" form, same as the Bot API
	Debug       bool

	// Auth is asked for the login code, and for the 2FA password when Password
	// is empty. Required only when there is no valid saved session.
	Auth Authenticator
}

// Client wraps a gotd MTProto client for one chat.
type Client struct {
	cfg     Config
	log     Logger
	handler MessageHandler

	client  *telegram.Client
	onReady func()
}

// New builds a client. handler is invoked for each message in the watched chat.
func New(cfg Config, log Logger, handler MessageHandler) *Client {
	return &Client{cfg: cfg, log: log, handler: handler}
}

// SetOnReady registers a callback fired once login has completed.
func (c *Client) SetOnReady(fn func()) { c.onReady = fn }

// Run authenticates if needed and then streams updates until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	dispatcher := tg.NewUpdateDispatcher()

	opts := telegram.Options{
		SessionStorage: &session.FileStorage{Path: c.cfg.SessionPath},
		UpdateHandler:  dispatcher,
	}
	c.client = telegram.NewClient(c.cfg.APIID, c.cfg.APIHash, opts)

	dispatcher.OnNewChannelMessage(func(ctx context.Context, _ tg.Entities, u *tg.UpdateNewChannelMessage) error {
		c.onMessage(ctx, u.Message)
		return nil
	})
	dispatcher.OnNewMessage(func(ctx context.Context, _ tg.Entities, u *tg.UpdateNewMessage) error {
		c.onMessage(ctx, u.Message)
		return nil
	})

	return c.client.Run(ctx, func(ctx context.Context) error {
		if err := c.authenticate(ctx); err != nil {
			return err
		}

		self, err := c.client.Self(ctx)
		if err != nil {
			return fmt.Errorf("fetching own account: %w", err)
		}
		c.log.Info("MTProto authenticated as %s (id %d)", displayName(self), self.ID)
		c.log.Info("watching chat %d for AC-AUTH-FAIL events", c.cfg.ChatID)

		if c.onReady != nil {
			c.onReady()
		}

		<-ctx.Done()
		return ctx.Err()
	})
}

// authenticate performs the interactive login flow when no valid session exists.
func (c *Client) authenticate(ctx context.Context) error {
	status, err := c.client.Auth().Status(ctx)
	if err != nil {
		return fmt.Errorf("checking auth status: %w", err)
	}
	if status.Authorized {
		return nil
	}

	if c.cfg.Auth == nil {
		return errors.New("no valid session and no way to ask for the login code")
	}

	c.log.Info("no valid session - starting interactive login for %s", c.cfg.Phone)
	flow := auth.NewFlow(
		userAuth{cfg: c.cfg, log: c.log},
		auth.SendCodeOptions{},
	)
	if err := c.client.Auth().IfNecessary(ctx, flow); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	c.log.Info("login successful - session saved to %s", c.cfg.SessionPath)
	return nil
}

// onMessage converts an incoming MTProto message and forwards it to the handler.
func (c *Client) onMessage(ctx context.Context, raw tg.MessageClass) {
	msg, ok := raw.(*tg.Message)
	if !ok {
		return // service message, etc.
	}

	chatID := c.chatIDOf(msg)
	if chatID == 0 {
		return
	}
	if c.cfg.Debug {
		c.log.Info("raw message: chat=%d id=%d text=%q", chatID, msg.ID, msg.Message)
	}
	if chatID != c.cfg.ChatID {
		return
	}

	c.handler(ctx, chatID, msg.Message)
}

// chatIDOf derives the "-100…" chat id used by this program's configuration
// from an MTProto peer.
func (c *Client) chatIDOf(msg *tg.Message) int64 {
	switch p := msg.PeerID.(type) {
	case *tg.PeerChannel:
		return channelIDOffset - p.ChannelID
	case *tg.PeerChat:
		return -p.ChatID
	case *tg.PeerUser:
		return p.UserID
	default:
		return 0
	}
}

// userAuth adapts the configured Authenticator to gotd's login flow.
type userAuth struct {
	cfg Config
	log Logger
}

func (u userAuth) Phone(context.Context) (string, error) { return u.cfg.Phone, nil }

func (u userAuth) Password(ctx context.Context) (string, error) {
	if u.cfg.Password != "" {
		return u.cfg.Password, nil
	}
	u.log.Info("this account has 2FA enabled - waiting for the password")
	return u.cfg.Auth.Password(ctx)
}

func (u userAuth) Code(ctx context.Context, _ *tg.AuthSentCode) (string, error) {
	u.log.Info("Telegram sent a login code to %s - waiting for it", u.cfg.Phone)
	return u.cfg.Auth.Code(ctx)
}

func (u userAuth) AcceptTermsOfService(_ context.Context, _ tg.HelpTermsOfService) error {
	return nil
}

func (u userAuth) SignUp(context.Context) (auth.UserInfo, error) {
	return auth.UserInfo{}, errors.New("this account is not registered; sign up in a Telegram app first")
}

func displayName(u *tg.User) string {
	if name := strings.TrimSpace(u.FirstName + " " + u.LastName); name != "" {
		return name
	}
	if u.Username != "" {
		return "@" + u.Username
	}
	return "(unnamed)"
}
