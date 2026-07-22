package config

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	ExitOK           = 0
	ExitRuntime      = 1
	ExitConfig       = 2
	ExitChatID       = 3
	ExitTelegramAuth = 4
	ExitNetwork      = 5
)

type Mode string

const (
	ModeHistory Mode = "history"
	ModeMTProto Mode = "mtproto"
	ModeBot     Mode = "bot"
)

type Config struct {
	Mode         Mode
	SkudUnionID  string
	SkudJWT      string
	SkudContract string
	SkudPassword string
	KeyName      string
	Debug        bool

	// History mode
	MAC             string
	PollInterval    time.Duration
	Lookback        time.Duration
	ProcessExisting bool

	// Telegram modes
	ChatID        int64
	TelegramToken string
	APIID         int
	APIHash       string
	Phone         string
	Password      string
	SessionPath   string
}

type Options struct {
	Port      int
	NoBrowser bool
}

type StartupError struct {
	Code       int
	Message    string
	Suggestion string
}

func (e *StartupError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s (%s)", e.Message, e.Suggestion)
	}
	return e.Message
}

func Load(args []string) (*Config, Settings, Options, error) {
	fs := flag.NewFlagSet("skudkey", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	flags := map[string]*string{}
	str := func(name, key, usage string) {
		flags[key] = fs.String(name, "", usage)
	}
	str("mode", "MODE", "where to read events: history | mtproto | bot")
	str("skud-union-id", "SKUD_UNION_ID", "Ufanet SKUD union id")
	str("skud-jwt", "SKUD_JWT", "SKUD JWT token")
	str("skud-contract", "SKUD_CONTRACT", "SKUD contract/login for automatic token refresh")
	str("skud-password", "SKUD_PASSWORD", "SKUD password for automatic token refresh")
	str("key-name", "KEY_NAME", "name to register new keys under")
	str("mac", "SKUD_MAC", "device MAC for history mode, e.g. 50-62-55-02-2b-f9")
	str("poll-interval", "POLL_INTERVAL", "history poll interval (default 30s)")
	str("lookback", "LOOKBACK", "history time window per poll (default 15m)")
	str("telegram-token", "TELEGRAM_TOKEN", "Telegram bot token")
	str("chat-id", "CHAT_ID", "Telegram chat id to watch")
	str("api-id", "API_ID", "MTProto api_id from my.telegram.org")
	str("api-hash", "API_HASH", "MTProto api_hash from my.telegram.org")
	str("phone", "PHONE", "phone number of the user account")
	str("password", "PASSWORD", "Telegram 2FA password, if enabled")
	str("session", "SESSION_PATH", "MTProto session file (default session.json)")

	flagDebug := fs.Bool("debug", false, "log every event received")
	flagExisting := fs.Bool("process-existing", false, "register keys already present in the first poll")
	flagPort := fs.Int("port", 8765, "port for the local web interface")
	flagNoBrowser := fs.Bool("no-browser", false, "do not open a browser on startup")

	if err := fs.Parse(args); err != nil {
		return nil, nil, Options{}, &StartupError{
			Code:       ExitConfig,
			Message:    "could not parse command-line flags: " + err.Error(),
			Suggestion: "run with --help to see all flags",
		}
	}

	loadDotEnv(".env")

	stored, err := LoadStored()
	if err != nil {
		stored = Settings{}
	}

	settings := Settings{}
	for _, key := range storedKeys {
		switch {
		case flags[key] != nil && strings.TrimSpace(*flags[key]) != "":
			settings[key] = strings.TrimSpace(*flags[key])
		case strings.TrimSpace(os.Getenv(key)) != "":
			settings[key] = strings.TrimSpace(os.Getenv(key))
		default:
			settings[key] = strings.TrimSpace(stored[key])
		}
	}
	if *flagDebug {
		settings["DEBUG"] = "1"
	}
	if *flagExisting {
		settings["PROCESS_EXISTING"] = "1"
	}

	opts := Options{Port: *flagPort, NoBrowser: *flagNoBrowser}

	cfg, err := FromSettings(settings)
	if err != nil {
		return nil, settings, opts, err
	}
	return cfg, settings, opts, nil
}

func FromSettings(s Settings) (*Config, error) {
	get := func(key string) string { return strings.TrimSpace(s[key]) }

	mode := Mode(strings.ToLower(get("MODE")))
	if mode == "" {
		mode = ModeHistory
	}
	if mode != ModeHistory && mode != ModeMTProto && mode != ModeBot {
		return nil, &StartupError{
			Code:       ExitConfig,
			Message:    fmt.Sprintf("invalid mode %q", string(mode)),
			Suggestion: `use "history", "mtproto" or "bot"`,
		}
	}

	cfg := &Config{
		Mode:         mode,
		SkudUnionID:  get("SKUD_UNION_ID"),
		SkudJWT:      get("SKUD_JWT"),
		SkudContract: get("SKUD_CONTRACT"),
		SkudPassword: get("SKUD_PASSWORD"),
		KeyName:      get("KEY_NAME"),
		Debug:        truthy(get("DEBUG")),

		MAC:             get("SKUD_MAC"),
		ProcessExisting: truthy(get("PROCESS_EXISTING")),

		TelegramToken: get("TELEGRAM_TOKEN"),
		APIHash:       get("API_HASH"),
		Phone:         get("PHONE"),
		Password:      get("PASSWORD"),
		SessionPath:   get("SESSION_PATH"),
	}
	if cfg.SessionPath == "" {
		cfg.SessionPath = "session.json"
	}

	var err error
	if cfg.PollInterval, err = duration(get("POLL_INTERVAL"), 30*time.Second); err != nil {
		return nil, &StartupError{
			Code: ExitConfig, Message: "invalid poll interval: " + err.Error(),
			Suggestion: `use a Go duration such as "30s" or "2m"`,
		}
	}
	if cfg.Lookback, err = duration(get("LOOKBACK"), 15*time.Minute); err != nil {
		return nil, &StartupError{
			Code: ExitConfig, Message: "invalid lookback: " + err.Error(),
			Suggestion: `use a Go duration such as "15m" or "1h"`,
		}
	}

	if v := get("CHAT_ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, &StartupError{
				Code:       ExitChatID,
				Message:    fmt.Sprintf("invalid chat id %q: must be a whole number (group ids are usually negative, e.g. -1001234567890)", v),
				Suggestion: "read chat.id from getUpdates",
			}
		}
		cfg.ChatID = id
	}

	if v := get("API_ID"); v != "" {
		id, err := strconv.Atoi(v)
		if err != nil {
			return nil, &StartupError{
				Code:       ExitConfig,
				Message:    fmt.Sprintf("invalid api id %q: must be a whole number", v),
				Suggestion: "copy api_id exactly as shown on my.telegram.org",
			}
		}
		cfg.APIID = id
	}

	return cfg, nil
}

func (c *Config) Missing() []string {
	var missing []string
	if c.SkudUnionID == "" {
		missing = append(missing, "union-id")
	}
	if c.KeyName == "" {
		missing = append(missing, "key-name")
	}
	if c.SkudJWT == "" && (c.SkudContract == "" || c.SkudPassword == "") {
		missing = append(missing, "credentials")
	}

	switch c.Mode {
	case ModeHistory:
		if c.MAC == "" {
			missing = append(missing, "mac")
		}
	case ModeBot:
		if c.ChatID == 0 {
			missing = append(missing, "chat-id")
		}
		if c.TelegramToken == "" {
			missing = append(missing, "bot-token")
		}
	case ModeMTProto:
		if c.ChatID == 0 {
			missing = append(missing, "chat-id")
		}
		if c.APIID == 0 {
			missing = append(missing, "api-id")
		}
		if c.APIHash == "" {
			missing = append(missing, "api-hash")
		}
		if c.Phone == "" {
			missing = append(missing, "phone")
		}
	}
	return missing
}

func duration(value string, def time.Duration) (time.Duration, error) {
	if value == "" {
		return def, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive, got %s", d)
	}
	return d, nil
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	defer func() {
		_ = scanner.Err()
	}()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" {
			continue
		}
		if _, present := os.LookupEnv(key); !present {
			_ = os.Setenv(key, value)
		}
	}
}
