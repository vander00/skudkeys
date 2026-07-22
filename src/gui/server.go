package gui

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"skudkey/src/app"
	"skudkey/src/config"
	"skudkey/src/logging"
	"skudkey/src/runner"
)

//go:embed index.html
var assets embed.FS

type Server struct {
	log    *logging.Logger
	keys   *KeyLog
	run    *runner.Runner
	auth   *authPrompt
	token  string
	quit   chan struct{}
	closed sync.Once

	mu       sync.Mutex
	settings config.Settings
}

func NewServer(log *logging.Logger, keys *KeyLog, run *runner.Runner, settings config.Settings) *Server {
	return &Server{
		log:      log,
		keys:     keys,
		run:      run,
		auth:     newAuthPrompt(),
		token:    randomToken(),
		quit:     make(chan struct{}),
		settings: settings,
	}
}

func (s *Server) Quit() <-chan struct{} { return s.quit }

func (s *Server) Auth() *authPrompt { return s.auth }

func (s *Server) Settings() config.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := config.Settings{}
	maps.Copy(out, s.settings)
	return out
}

func (s *Server) Listen(port int) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, "", fmt.Errorf("could not bind a local port: %w", err)
		}
	}
	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), s.token)
	return ln, url, nil
}

func (s *Server) Serve(ln net.Listener, openInBrowser bool, url string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/status", s.guard(s.handleStatus))
	mux.HandleFunc("/api/keys", s.guard(s.handleKeys))
	mux.HandleFunc("/api/settings", s.guard(s.handleSettings))
	mux.HandleFunc("/api/control", s.guard(s.handleControl))
	mux.HandleFunc("/api/auth", s.guard(s.handleAuth))

	s.log.Info("web interface ready at %s", url)
	if openInBrowser {
		if err := openBrowser(url); err != nil {
			s.log.Warn("could not open a browser automatically: %v - open the URL above yourself", err)
		}
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
				return
			}
		}
		token := r.Header.Get("X-Token")
		if token == "" {
			token = r.URL.Query().Get("t")
		}
		if token != s.token {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page, err := assets.ReadFile("index.html")
	if err != nil {
		http.Error(w, "interface not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

type statusResponse struct {
	Running   bool     `json:"running"`
	Paused    bool     `json:"paused"`
	Mode      string   `json:"mode"`
	Uptime    string   `json:"uptime"`
	Processed int      `json:"processed"`
	KeyName   string   `json:"keyName"`
	Token     string   `json:"token"`
	UnionID   string   `json:"unionId"`
	ChatID    int64    `json:"chatId"`
	MAC       string   `json:"mac"`
	LastError string   `json:"lastError"`
	Missing   []string `json:"missing"`
	CanLogin  bool     `json:"canLogin"`
	Prompt    string   `json:"prompt"`
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	cfg, cfgErr := config.FromSettings(s.Settings())

	resp := statusResponse{
		Prompt:    s.auth.Pending(),
		Missing:   []string{},
		LastError: s.run.LastError(),
	}
	if cfgErr != nil {
		resp.LastError = cfgErr.Error()
	}
	if cfg != nil {
		resp.Mode = string(cfg.Mode)
		resp.UnionID = cfg.SkudUnionID
		resp.ChatID = cfg.ChatID
		resp.MAC = cfg.MAC
		resp.KeyName = cfg.KeyName
		if m := cfg.Missing(); len(m) > 0 {
			resp.Missing = m
		}
	}

	if a := s.run.App(); a != nil {
		resp.Running = true
		resp.Paused = a.Paused()
		resp.Uptime = a.Uptime().String()
		resp.Processed = a.Processed()
		resp.KeyName = a.KeyName()
		resp.Token = a.MaskedToken()
		resp.CanLogin = a.CanLogin()
		if e := a.LastError(); e != "" {
			resp.LastError = e
		}
	}

	writeJSON(w, resp)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	events, release := s.keys.Subscribe()
	defer release()

	for _, e := range s.keys.Events() {
		writeSSE(w, e)
	}
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case e, ok := <-events:
			if !ok {
				return
			}
			writeSSE(w, e)
			flusher.Flush()
		}
	}
}

type settingsResponse struct {
	Values  map[string]string `json:"values"`
	Secrets map[string]bool   `json:"secrets"`
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		current := s.Settings()
		resp := settingsResponse{
			Values:  map[string]string{},
			Secrets: map[string]bool{},
		}
		for k, v := range current {
			if config.SecretKeys[k] {
				resp.Secrets[k] = v != ""
				continue
			}
			resp.Values[k] = v
		}
		writeJSON(w, resp)

	case http.MethodPost:
		var incoming map[string]string
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "could not read the settings: "+err.Error(), http.StatusBadRequest)
			return
		}

		merged := s.Settings()
		for k, v := range incoming {
			v = strings.TrimSpace(v)
			// An untouched secret arrives empty and must keep its stored value.
			if config.SecretKeys[k] && v == "" {
				continue
			}
			merged[k] = v
		}

		cfg, err := config.FromSettings(merged)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := config.Save(merged); err != nil {
			http.Error(w, "could not save the settings: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.mu.Lock()
		s.settings = merged
		s.mu.Unlock()
		s.log.Info("settings saved")

		if s.run.Running() {
			s.log.Info("restarting the watcher with the new settings")
			s.run.Stop()
			if err := s.run.Start(cfg, s.auth); err != nil {
				s.log.Error("could not restart: %v", err)
			}
		}
		writeJSON(w, map[string]any{"ok": true, "missing": cfg.Missing()})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type controlRequest struct {
	Action string `json:"action"`
	Value  string `json:"value"`
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req controlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}

	needsApp := map[string]bool{
		"pause": true, "resume": true, "login": true, "set-token": true,
	}
	a := s.run.App()
	if needsApp[req.Action] && a == nil {
		http.Error(w, "the watcher is not running", http.StatusConflict)
		return
	}

	switch req.Action {
	case "start":
		cfg, err := config.FromSettings(s.Settings())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.run.Start(cfg, s.auth); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	case "stop":
		s.run.Stop()

	case "pause":
		if a.SetPaused(true) {
			s.log.Info("already paused")
		} else {
			s.log.Info("paused - events ignored until resumed")
		}

	case "resume":
		if !a.SetPaused(false) {
			s.log.Info("already running")
		} else {
			s.log.Info("resumed")
		}

	case "login":
		if !a.CanLogin() {
			http.Error(w, "no contract credentials configured - set them in settings", http.StatusBadRequest)
			return
		}
		if err := a.Login(r.Context()); err != nil {
			http.Error(w, "login failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		s.log.Info("SKUD token refreshed (now %s)", a.MaskedToken())

	case "set-name":
		name := strings.TrimSpace(req.Value)
		if name == "" {
			http.Error(w, "the key name cannot be empty", http.StatusBadRequest)
			return
		}
		previous := s.Settings()["KEY_NAME"]
		if a != nil {
			previous = a.SetKeyName(name)
		}
		s.persist("KEY_NAME", name)
		s.log.Info("key name changed from %q to %q - new keys will use it", previous, name)

	case "set-token":
		token := strings.TrimSpace(req.Value)
		if token == "" {
			http.Error(w, "the token cannot be empty", http.StatusBadRequest)
			return
		}
		masked := a.HotSwapToken(token)
		s.persist("SKUD_JWT", token)
		s.log.Info("SKUD JWT hot-swapped (now %s)", masked)

	case "quit":
		s.log.Info("shutdown requested")
		s.closed.Do(func() { close(s.quit) })

	default:
		http.Error(w, "unknown action "+req.Action, http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	value := strings.TrimSpace(req.Value)
	if value == "" {
		http.Error(w, "the value cannot be empty", http.StatusBadRequest)
		return
	}
	if err := s.auth.Submit(value); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) persist(key, value string) {
	s.mu.Lock()
	s.settings[key] = value
	merged := config.Settings{}
	maps.Copy(merged, s.settings)
	s.mu.Unlock()

	if err := config.Save(merged); err != nil {
		s.log.Warn("could not save the change: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeSSE(w http.ResponseWriter, e app.KeyEvent) {
	payload, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", payload)
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
