// Package store provides JSON file-based persistence for API keys and the
// upstream PAT pool.
package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"qoder2api/logs"
	"qoder2api/stats"
)

// ErrDuplicateKey is returned by AddKey when an identical key already exists.
var ErrDuplicateKey = errors.New("api key already exists")

// ErrDuplicateToken is returned by AddToken when the same PAT is already in
// the pool.
var ErrDuplicateToken = errors.New("pat already exists")

// APIKey represents a single API key entry.
type APIKey struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
}

// Token is one upstream Qoder PAT in the pool. Each token is a separate
// account: its own session, its own concurrency slots, its own quota and
// billing cycle.
type Token struct {
	ID        string `json:"id"`
	PAT       string `json:"pat"`
	Note      string `json:"note"`
	Weight    int    `json:"weight"`
	Disabled  bool   `json:"disabled,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// TokenPatch carries the editable fields of a pool entry. Pointers distinguish
// "leave alone" from "set to the zero value" (a weight of 0 is invalid, but
// Disabled=false is a real request to re-enable an entry).
type TokenPatch struct {
	Note     *string
	Weight   *int
	Disabled *bool
}

// Weight bounds. The weight is a relative share of traffic, not a percentage,
// so it stays small and the picker's arithmetic cannot overflow.
const (
	DefaultTokenWeight = 1
	MinTokenWeight     = 1
	MaxTokenWeight     = 100
)

// ValidateTokenWeight checks that n is a usable relative traffic share.
func ValidateTokenWeight(n int) error {
	if n < MinTokenWeight || n > MaxTokenWeight {
		return fmt.Errorf("权重需在 %d-%d 之间", MinTokenWeight, MaxTokenWeight)
	}
	return nil
}

// normalizeWeight maps an unusable weight (0 in a hand-edited file, or an
// out-of-range one) onto the nearest valid value instead of rejecting the file.
func normalizeWeight(n int) int {
	if n < MinTokenWeight {
		return DefaultTokenWeight
	}
	if n > MaxTokenWeight {
		return MaxTokenWeight
	}
	return n
}

// Config is the on-disk JSON structure.
type Config struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Password string   `json:"password"`
	APIKeys  []APIKey `json:"api_keys"`
	// Tokens is the upstream PAT pool. LegacyPAT is read once at load time to
	// migrate a pre-pool data.json into a single-entry pool; it is never
	// written back, so the pool stays the only copy of the secret on disk.
	LegacyPAT string      `json:"pat,omitempty"`
	Tokens    []Token     `json:"tokens"`
	Stats     *stats.Data `json:"stats,omitempty"`
	// Logs is the persisted request-log ring (metadata only), flushed out of
	// band by the logs recorder — the JSON equivalent of Buddy-2API's logs
	// table.
	Logs []logs.LogEntry `json:"logs,omitempty"`
	// Request-log limits: RetentionDays bounds how long entries live,
	// MaxEntries the slice length, so data.json (rewritten on every flush)
	// cannot grow without limit.
	LogRetentionDays int `json:"log_retention_days"`
	LogMaxEntries    int `json:"log_max_entries"`
	// ChatTimeoutSeconds bounds how long the upstream chat stream may take
	// to start responding (time to response headers). IdleTimeoutSeconds
	// bounds how long an established SSE stream may stay silent.
	ChatTimeoutSeconds int `json:"chat_timeout_seconds"`
	IdleTimeoutSeconds int `json:"idle_timeout_seconds"`
}

// DefaultHost is the default listen host.
const DefaultHost = "0.0.0.0"

// DefaultPort is the default listen port.
const DefaultPort = 10081

// DefaultPassword is the default admin password.
const DefaultPassword = "password"

// Chat stream timeout bounds (seconds). The max cap also guards against
// overflow when callers convert seconds to time.Duration nanoseconds — a
// value beyond ~292 years wraps negative and silently disables the timeout.
const (
	DefaultChatTimeoutSeconds = 120
	MaxChatTimeoutSeconds     = 3600
	DefaultIdleTimeoutSeconds = 300
	MaxIdleTimeoutSeconds     = 3600
)

// Request-log limits mirrored from the logs package, so callers that only see
// the store (admin config validation) need no logs import.
const (
	DefaultLogRetentionDays = logs.DefaultRetentionDays
	MaxLogRetentionDays     = logs.MaxRetentionDays
	DefaultLogMaxEntries    = logs.DefaultMaxEntries
	MinLogMaxEntries        = logs.MinMaxEntries
	MaxLogEntriesHardCap    = logs.MaxEntriesHardCap
)

// ValidateLogRetentionDays checks that n is a usable retention in days.
func ValidateLogRetentionDays(n int) error {
	if n < 1 || n > MaxLogRetentionDays {
		return fmt.Errorf("日志保留天数需在 1-%d 之间", MaxLogRetentionDays)
	}
	return nil
}

// ValidateLogMaxEntries checks that n is a usable entry cap.
func ValidateLogMaxEntries(n int) error {
	if n < MinLogMaxEntries || n > MaxLogEntriesHardCap {
		return fmt.Errorf("日志条数上限需在 %d-%d 之间", MinLogMaxEntries, MaxLogEntriesHardCap)
	}
	return nil
}

// ValidateTimeoutSeconds checks that n is a usable timeout in seconds.
func ValidateTimeoutSeconds(n, max int) error {
	if n < 1 || n > max {
		return fmt.Errorf("超时需在 1-%d 秒之间", max)
	}
	return nil
}

// Store manages persistent configuration with thread-safe access.
type Store struct {
	mu       sync.RWMutex
	filePath string
	config   *Config
	// tokensGen counts pool mutations. Bridge-side pool reconciliation compares
	// it instead of diffing token slices, so a PAT never leaves the store on the
	// hot path and a hand-edited file is picked up as soon as it is loaded.
	tokensGen atomic.Int64
}

// New creates a Store backed by the given file path.
// If the file does not exist, a default config is created.
func New(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
		config: &Config{
			Host:               DefaultHost,
			Port:               DefaultPort,
			ChatTimeoutSeconds: DefaultChatTimeoutSeconds,
			IdleTimeoutSeconds: DefaultIdleTimeoutSeconds,
			LogRetentionDays:   DefaultLogRetentionDays,
			LogMaxEntries:      DefaultLogMaxEntries,
			APIKeys:            []APIKey{},
			Tokens:             []Token{},
		},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return s.saveLocked()
		}
		return err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("store: parse %s: %w", s.filePath, err)
	}
	needsSave := false
	if cfg.APIKeys == nil {
		cfg.APIKeys = []APIKey{}
		needsSave = true
	}
	if cfg.Host == "" {
		cfg.Host = DefaultHost
		needsSave = true
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
		needsSave = true
	}
	if cfg.Password == "" {
		cfg.Password = DefaultPassword
		needsSave = true
	}
	if cfg.ChatTimeoutSeconds <= 0 {
		cfg.ChatTimeoutSeconds = DefaultChatTimeoutSeconds
		needsSave = true
	}
	if cfg.IdleTimeoutSeconds <= 0 {
		cfg.IdleTimeoutSeconds = DefaultIdleTimeoutSeconds
		needsSave = true
	}
	if cfg.LogRetentionDays <= 0 {
		cfg.LogRetentionDays = DefaultLogRetentionDays
		needsSave = true
	}
	if cfg.LogMaxEntries <= 0 {
		cfg.LogMaxEntries = DefaultLogMaxEntries
		needsSave = true
	}
	// Clamp out-of-range values (hand-edited files, older versions) instead
	// of rejecting the whole file.
	if cfg.ChatTimeoutSeconds > MaxChatTimeoutSeconds {
		cfg.ChatTimeoutSeconds = MaxChatTimeoutSeconds
		needsSave = true
	}
	if cfg.IdleTimeoutSeconds > MaxIdleTimeoutSeconds {
		cfg.IdleTimeoutSeconds = MaxIdleTimeoutSeconds
		needsSave = true
	}
	tokens, tokensFixed := sanitizeTokens(cfg.Tokens)
	// One-time migration: a pre-pool data.json carries the single PAT in "pat".
	// It becomes the pool's first entry, and the legacy field is dropped so the
	// secret has exactly one home on disk.
	if cfg.LegacyPAT != "" {
		tokens = append(tokens, Token{
			PAT:       cfg.LegacyPAT,
			Note:      "原单账号",
			Weight:    DefaultTokenWeight,
			CreatedAt: time.Now().Unix(),
		})
		cfg.LegacyPAT = ""
		tokens, tokensFixed = sanitizeTokens(tokens)
		needsSave = true
	}
	if len(tokens) != len(cfg.Tokens) || tokensFixed {
		needsSave = true
	}
	cfg.Tokens = tokens
	s.config = &cfg
	s.tokensGen.Store(1)
	// Persist migrated defaults so the file stays in sync
	if needsSave {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// fsync before rename: without it a crash can leave a truncated or empty
	// data.json on some filesystems (rename is not a barrier for unflushed
	// file contents).
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.filePath)
}

func (s *Store) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// --- Server Config ---

func (s *Store) GetHost() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Host
}

func (s *Store) GetPort() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Port
}

func (s *Store) SetHostPort(host string, port int) error {
	s.mu.Lock()
	s.config.Host = host
	s.config.Port = port
	s.mu.Unlock()
	return s.save()
}

// --- Stream Timeouts ---

// GetChatTimeoutSeconds returns the chat response-header timeout in seconds
// (0-normalized to the default; clamped to the max).
func (s *Store) GetChatTimeoutSeconds() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeTimeout(s.config.ChatTimeoutSeconds, DefaultChatTimeoutSeconds, MaxChatTimeoutSeconds)
}

// GetIdleTimeoutSeconds returns the SSE idle timeout in seconds.
func (s *Store) GetIdleTimeoutSeconds() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeTimeout(s.config.IdleTimeoutSeconds, DefaultIdleTimeoutSeconds, MaxIdleTimeoutSeconds)
}

// SetChatTimeoutSeconds validates and persists the chat response-header
// timeout in seconds.
func (s *Store) SetChatTimeoutSeconds(n int) error {
	if err := ValidateTimeoutSeconds(n, MaxChatTimeoutSeconds); err != nil {
		return err
	}
	s.mu.Lock()
	s.config.ChatTimeoutSeconds = n
	s.mu.Unlock()
	return s.save()
}

// SetIdleTimeoutSeconds validates and persists the SSE idle timeout in
// seconds.
func (s *Store) SetIdleTimeoutSeconds(n int) error {
	if err := ValidateTimeoutSeconds(n, MaxIdleTimeoutSeconds); err != nil {
		return err
	}
	s.mu.Lock()
	s.config.IdleTimeoutSeconds = n
	s.mu.Unlock()
	return s.save()
}

// normalizeTimeout maps 0 to def and clamps above max.
func normalizeTimeout(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// --- Password ---

func (s *Store) GetPassword() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config.Password == "" {
		return DefaultPassword
	}
	return s.config.Password
}

func (s *Store) SetPassword(password string) error {
	s.mu.Lock()
	s.config.Password = password
	s.mu.Unlock()
	return s.save()
}

// --- Token pool ---

// ListTokens returns a copy of the pool in config order. The PAT material is
// included: callers are the bridge-side pool (which signs requests) and the
// admin API (which masks it before answering).
func (s *Store) ListTokens() []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Token, len(s.config.Tokens))
	copy(out, s.config.Tokens)
	return out
}

// TokensGen returns the pool's mutation generation. It only ever increases.
func (s *Store) TokensGen() int64 { return s.tokensGen.Load() }

// AddToken appends a PAT to the pool. An empty weight selects the default.
// Returns ErrDuplicateToken when the same PAT is already configured.
func (s *Store) AddToken(pat, note string, weight int) (*Token, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, fmt.Errorf("令牌不能为空")
	}
	if weight == 0 {
		weight = DefaultTokenWeight
	}
	if err := ValidateTokenWeight(weight); err != nil {
		return nil, err
	}
	id, err := GenerateID()
	if err != nil {
		return nil, fmt.Errorf("generate id: %w", err)
	}
	entry := &Token{
		ID:        id,
		PAT:       pat,
		Note:      strings.TrimSpace(note),
		Weight:    weight,
		CreatedAt: time.Now().Unix(),
	}
	s.mu.Lock()
	for _, t := range s.config.Tokens {
		if t.PAT == pat {
			s.mu.Unlock()
			return nil, ErrDuplicateToken
		}
	}
	s.config.Tokens = append(s.config.Tokens, *entry)
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return nil, err
	}
	s.tokensGen.Add(1)
	return entry, nil
}

// PatchToken applies a partial update to the pool entry with the given ID.
func (s *Store) PatchToken(id string, p TokenPatch) error {
	s.mu.Lock()
	found := false
	for i := range s.config.Tokens {
		if s.config.Tokens[i].ID != id {
			continue
		}
		found = true
		if p.Note != nil {
			s.config.Tokens[i].Note = strings.TrimSpace(*p.Note)
		}
		if p.Weight != nil {
			if err := ValidateTokenWeight(*p.Weight); err != nil {
				s.mu.Unlock()
				return err
			}
			s.config.Tokens[i].Weight = *p.Weight
		}
		if p.Disabled != nil {
			s.config.Tokens[i].Disabled = *p.Disabled
		}
		break
	}
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("token not found: %s", id)
	}
	if err := s.save(); err != nil {
		return err
	}
	s.tokensGen.Add(1)
	return nil
}

// DeleteToken removes the pool entry with the given ID.
func (s *Store) DeleteToken(id string) error {
	s.mu.Lock()
	found := false
	filtered := s.config.Tokens[:0]
	for _, t := range s.config.Tokens {
		if t.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, t)
	}
	s.config.Tokens = filtered
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("token not found: %s", id)
	}
	if err := s.save(); err != nil {
		return err
	}
	s.tokensGen.Add(1)
	return nil
}

// GetToken returns the pool entry with the given ID.
func (s *Store) GetToken(id string) (Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.config.Tokens {
		if t.ID == id {
			return t, true
		}
	}
	return Token{}, false
}

// sanitizeTokens repairs a pool read from disk: blank out unusable entries,
// clamp weights, fill in missing IDs and drop duplicate PATs. It reports
// whether anything was changed so the caller can decide to persist the fix.
func sanitizeTokens(in []Token) ([]Token, bool) {
	changed := false
	seen := make(map[string]bool, len(in))
	out := make([]Token, 0, len(in))
	for _, t := range in {
		t.PAT = strings.TrimSpace(t.PAT)
		if t.PAT == "" || seen[t.PAT] {
			changed = true
			continue
		}
		seen[t.PAT] = true
		if w := normalizeWeight(t.Weight); w != t.Weight {
			t.Weight, changed = w, true
		}
		if t.ID == "" {
			if id, err := GenerateID(); err == nil {
				t.ID, changed = id, true
			}
		}
		if t.CreatedAt == 0 {
			t.CreatedAt, changed = time.Now().Unix(), true
		}
		out = append(out, t)
	}
	return out, changed
}

// --- Stats ---

// LoadStats returns a deep copy of the persisted stats snapshot, or nil if
// none exists. A copy is returned so callers can never race with concurrent
// save() calls that marshal the live snapshot.
func (s *Store) LoadStats() *stats.Data {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config.Stats == nil {
		return nil
	}
	return s.config.Stats.Clone()
}

// SaveStats persists the stats snapshot into the config file.
func (s *Store) SaveStats(d *stats.Data) error {
	s.mu.Lock()
	s.config.Stats = d
	s.mu.Unlock()
	return s.save()
}

// --- Request Logs ---

// LoadLogs returns a copy of the persisted request-log entries, or nil if
// none exist — copied so the caller never aliases the marshaled slice.
func (s *Store) LoadLogs() []logs.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.config.Logs) == 0 {
		return nil
	}
	return append([]logs.LogEntry(nil), s.config.Logs...)
}

// SaveLogs persists the request-log entries into the config file.
func (s *Store) SaveLogs(entries []logs.LogEntry) error {
	s.mu.Lock()
	s.config.Logs = entries
	s.mu.Unlock()
	return s.save()
}

// GetLogRetentionDays returns the configured log retention in days
// (0-normalized to the default; clamped to the max).
func (s *Store) GetLogRetentionDays() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n := s.config.LogRetentionDays; n > 0 {
		if n > MaxLogRetentionDays {
			return MaxLogRetentionDays
		}
		return n
	}
	return DefaultLogRetentionDays
}

// SetLogRetentionDays validates and persists the log retention in days.
func (s *Store) SetLogRetentionDays(n int) error {
	if err := ValidateLogRetentionDays(n); err != nil {
		return err
	}
	s.mu.Lock()
	s.config.LogRetentionDays = n
	s.mu.Unlock()
	return s.save()
}

// GetLogMaxEntries returns the configured log entry cap
// (0-normalized to the default; clamped into its valid range).
func (s *Store) GetLogMaxEntries() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n := s.config.LogMaxEntries; n > 0 {
		if n < MinLogMaxEntries {
			return MinLogMaxEntries
		}
		if n > MaxLogEntriesHardCap {
			return MaxLogEntriesHardCap
		}
		return n
	}
	return DefaultLogMaxEntries
}

// SetLogMaxEntries validates and persists the log entry cap.
func (s *Store) SetLogMaxEntries(n int) error {
	if err := ValidateLogMaxEntries(n); err != nil {
		return err
	}
	s.mu.Lock()
	s.config.LogMaxEntries = n
	s.mu.Unlock()
	return s.save()
}

// --- API Keys ---

// ListKeys returns a copy of all API keys.
func (s *Store) ListKeys() []APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]APIKey, len(s.config.APIKeys))
	copy(out, s.config.APIKeys)
	return out
}

// AddKey creates a new API key. If key is empty, a random one is generated.
// Returns an error if the key already exists (duplicate) or generation fails.
func (s *Store) AddKey(key, note string) (*APIKey, error) {
	if key == "" {
		var err error
		key, err = GenerateAPIKey()
		if err != nil {
			return nil, fmt.Errorf("generate api key: %w", err)
		}
	}
	id, err := GenerateID()
	if err != nil {
		return nil, fmt.Errorf("generate id: %w", err)
	}
	entry := &APIKey{
		ID:        id,
		Key:       key,
		Note:      note,
		CreatedAt: time.Now().Unix(),
	}
	s.mu.Lock()
	for _, k := range s.config.APIKeys {
		if k.Key == key {
			s.mu.Unlock()
			return nil, ErrDuplicateKey
		}
	}
	s.config.APIKeys = append(s.config.APIKeys, *entry)
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return nil, err
	}
	return entry, nil
}

// DeleteKey removes the API key with the given ID.
func (s *Store) DeleteKey(id string) error {
	s.mu.Lock()
	found := false
	filtered := s.config.APIKeys[:0]
	for _, k := range s.config.APIKeys {
		if k.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, k)
	}
	s.config.APIKeys = filtered
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("key not found: %s", id)
	}
	return s.save()
}

// ValidateKey returns true if the given key exists in the store.
// Comparison is constant-time to avoid leaking key material via timing.
func (s *Store) ValidateKey(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kb := []byte(key)
	for _, k := range s.config.APIKeys {
		// ConstantTimeCompare returns 1 only when lengths match and bytes equal.
		if subtle.ConstantTimeCompare([]byte(k.Key), kb) == 1 {
			return true
		}
	}
	return false
}

// LookupKey returns the metadata (ID, note) of the given key and whether it
// exists. Comparison is constant-time, as in ValidateKey: the key material is
// a secret and must not leak through early-exit timing either.
func (s *Store) LookupKey(key string) (APIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kb := []byte(key)
	for _, k := range s.config.APIKeys {
		if subtle.ConstantTimeCompare([]byte(k.Key), kb) == 1 {
			return k, true
		}
	}
	return APIKey{}, false
}

// --- Generators ---

// GenerateAPIKey returns a random "sk-" prefixed key (32 hex chars).
func GenerateAPIKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(b), nil
}

// GenerateID returns a short random hex ID.
func GenerateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
