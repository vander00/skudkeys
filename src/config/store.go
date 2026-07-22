package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Settings map[string]string

var storedKeys = []string{
	"MODE", "SKUD_UNION_ID", "SKUD_JWT", "SKUD_CONTRACT", "SKUD_PASSWORD",
	"KEY_NAME", "DEBUG",
	"SKUD_MAC", "POLL_INTERVAL", "LOOKBACK", "PROCESS_EXISTING",
	"CHAT_ID", "TELEGRAM_TOKEN", "API_ID", "API_HASH", "PHONE", "PASSWORD",
	"SESSION_PATH",
}

var SecretKeys = map[string]bool{
	"SKUD_JWT": true, "SKUD_PASSWORD": true, "TELEGRAM_TOKEN": true,
	"API_HASH": true, "PASSWORD": true,
}

func StorePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config directory: %w", err)
	}
	return filepath.Join(dir, "skudkey", "config.json"), nil
}

func LoadStored() (Settings, error) {
	path, err := StorePath()
	if err != nil {
		return Settings{}, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s == nil {
		s = Settings{}
	}
	return s, nil
}

func Save(s Settings) error {
	path, err := StorePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	clean := Settings{}
	for _, k := range storedKeys {
		if v := s[k]; v != "" {
			clean[k] = v
		}
	}

	data, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding settings: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}
