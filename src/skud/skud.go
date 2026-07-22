package skud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const apiBase = "https://dom.ufanet.ru"

type Config struct {
	UnionID  string
	Token    string
	KeyName  string
	Contract string
	Password string
}

type Client struct {
	mu      sync.RWMutex
	token   string
	unionID string
	keyName string

	contract string
	password string

	http *http.Client
	base string
}

func New(cfg Config) *Client {
	return &Client{
		token:    normalizeToken(cfg.Token),
		unionID:  cfg.UnionID,
		keyName:  cfg.KeyName,
		contract: cfg.Contract,
		password: cfg.Password,
		http:     &http.Client{Timeout: 30 * time.Second},
		base:     apiBase,
	}
}

func (c *Client) CanLogin() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.contract != "" && c.password != ""
}

func (c *Client) Login(ctx context.Context) error {
	c.mu.RLock()
	contract, password := c.contract, c.password
	c.mu.RUnlock()

	if contract == "" || password == "" {
		return errors.New("no SKUD contract credentials configured (set --skud-contract and --skud-password)")
	}

	payload, err := json.Marshal(map[string]string{"contract": contract, "password": password})
	if err != nil {
		return fmt.Errorf("encoding login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api-token-auth/", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting the SKUD auth endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("SKUD rejected the contract credentials (HTTP %d): %s", resp.StatusCode, snippet(body))
		}
		return fmt.Errorf("SKUD auth returned HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	var parsed struct {
		Token  string `json:"token"`
		Access string `json:"access"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decoding login response: %w", err)
	}
	token := parsed.Token
	if token == "" {
		token = parsed.Access
	}
	if token == "" {
		return fmt.Errorf("login response contained no token: %s", snippet(body))
	}

	c.SetToken(token)
	return nil
}

func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = normalizeToken(token)
}

func normalizeToken(token string) string {
	t := strings.TrimSpace(token)
	for _, prefix := range []string{"JWT ", "jwt ", "Bearer ", "bearer "} {
		if after, ok := strings.CutPrefix(t, prefix); ok {
			return strings.TrimSpace(after)
		}
	}
	return t
}

func (c *Client) KeyName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keyName
}

func (c *Client) SetKeyName(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyName = name
}

func (c *Client) MaskedToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return maskSecret(c.token)
}

type KeyError struct {
	StatusCode int
	Expired    bool
	Msg        string
}

func (e *KeyError) Error() string { return e.Msg }

func (e *KeyError) IsTokenExpired() bool { return e.Expired }

func (c *Client) CreateKey(ctx context.Context, key string) error {
	c.mu.RLock()
	token, unionID, name := c.token, c.unionID, c.keyName
	c.mu.RUnlock()

	payload, err := json.Marshal(map[string]string{"key": key, "name": name})
	if err != nil {
		return fmt.Errorf("encoding request body: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v3/frontend/skud/union/%s/key/create/", c.base, unionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "JWT "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return &KeyError{Msg: fmt.Sprintf("network error contacting SKUD API: %v", err)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return &KeyError{
			StatusCode: resp.StatusCode,
			Expired:    true,
			Msg:        fmt.Sprintf("SKUD API returned %d (unauthorized) - the JWT token looks expired and must be replaced manually", resp.StatusCode),
		}
	default:
		return &KeyError{
			StatusCode: resp.StatusCode,
			Msg:        fmt.Sprintf("SKUD API returned HTTP %d: %s", resp.StatusCode, snippet(body)),
		}
	}
}

func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	c.mu.RLock()
	token, unionID := c.token, c.unionID
	c.mu.RUnlock()

	endpoint := fmt.Sprintf("%s/api/v3/frontend/skud/union/%s/key/?page=1&page_size=10000", c.base, unionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("building key list request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "JWT "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting the SKUD key list API: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			_ = fmt.Errorf("failed to close response body: %s", err)
		}
	}()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &KeyError{
			StatusCode: resp.StatusCode,
			Expired:    true,
			Msg:        fmt.Sprintf("SKUD key list returned %d (unauthorized) - the JWT token looks expired", resp.StatusCode),
		}
	default:
		return nil, fmt.Errorf("SKUD key list returned HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	var parsed struct {
		Count   int `json:"count"`
		Results []struct {
			KeyValue string `json:"key_value"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding key list response: %w", err)
	}

	keys := make([]string, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		keys = append(keys, r.KeyValue)
	}
	return keys, nil
}

// Event is one entry of the device command history.
type Event struct {
	UUID    string `json:"uuid"`
	MAC     string `json:"mac"`
	Command string `json:"command"`
	Topic   string `json:"topic"`
	Payload string `json:"payload"`
	Time    int64  `json:"time"`
}

func (c *Client) History(ctx context.Context, mac string, start, end int64, pageSize int) ([]Event, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	payload, err := json.Marshal(map[string]any{
		"mac":        mac,
		"time_start": start,
		"time_end":   end,
		"tele":       false,
		"page":       0,
		"page_size":  strconv.Itoa(pageSize),
	})
	if err != nil {
		return nil, fmt.Errorf("encoding history request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v3/frontend/skud/commands_history/", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building history request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "JWT "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting the SKUD history API: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			_ = fmt.Errorf("failed to close response body: %s", err)
		}
	}()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
	case resp.StatusCode == http.StatusNotFound:
		// holds no records
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &KeyError{
			StatusCode: resp.StatusCode,
			Expired:    true,
			Msg:        fmt.Sprintf("SKUD history returned %d (unauthorized) - the JWT token looks expired", resp.StatusCode),
		}
	default:
		return nil, fmt.Errorf("SKUD history returned HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	var parsed struct {
		Status  string  `json:"status"`
		Results []Event `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding history response: %w", err)
	}
	return parsed.Results, nil
}

func maskSecret(s string) string {
	if s == "" {
		return "(unset)"
	}
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}

func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if s == "" {
		return "(empty response body)"
	}
	const max = 300
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
