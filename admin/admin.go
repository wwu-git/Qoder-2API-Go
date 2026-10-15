// Package admin provides WebUI management for the API bridge:
// PAT configuration, API key CRUD, model listing, and password-protected access.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"qoder2api/auth"
	"qoder2api/bridge"
	"qoder2api/logs"
	"qoder2api/models"
	"qoder2api/stats"
	"qoder2api/store"
)

const sessionDuration = 24 * time.Hour

// adminMaxBody caps JSON request bodies handled by the admin API.
const adminMaxBody = 1 << 16 // 64 KiB

// Admin manages the web UI and admin API endpoints.
type Admin struct {
	store        *store.Store
	modelFetcher ModelFetcher
	stats        *stats.Recorder
	logRec       *logs.Recorder
	pool         *bridge.Pool
	// verifyPAT checks a credential against the gateway before it is trusted
	// with traffic. It is a field so a test can stub the gateway; production
	// uses bridge.VerifyPAT.
	verifyPAT func(ctx context.Context, pat string) (*auth.AccountStatus, error)
	sessions  map[string]time.Time
	sessionMu sync.Mutex
	limiter   *loginLimiter
}

// ModelFetcher returns the current model catalog (dynamic or fallback).
type ModelFetcher func(ctx context.Context) []string

// New creates an Admin instance. rec, lr and pool may be nil.
func New(s *store.Store, mf ModelFetcher, rec *stats.Recorder, lr *logs.Recorder, pool *bridge.Pool) *Admin {
	return &Admin{
		store:        s,
		modelFetcher: mf,
		stats:        rec,
		logRec:       lr,
		pool:         pool,
		verifyPAT:    bridge.VerifyPAT,
		sessions:     make(map[string]time.Time),
		limiter:      newLoginLimiter(),
	}
}

// RegisterRoutes registers all admin API routes on the given mux.
//
// The WebUI itself is served by the web package (pages under /admin, assets
// under /admin/assets/); this mux section only owns the JSON API under
// /admin/api/*.
func (a *Admin) RegisterRoutes(mux *http.ServeMux) {
	// Auth endpoints (no auth required)
	mux.HandleFunc("/admin/api/login", a.handleLogin)
	mux.HandleFunc("/admin/api/logout", a.handleLogout)
	mux.HandleFunc("/admin/api/auth", a.handleAuth)

	// Protected API endpoints (require auth)
	mux.HandleFunc("/admin/api/keys", a.requireAuth(a.handleKeys))
	mux.HandleFunc("/admin/api/tokens", a.requireAuth(a.handleTokens))
	mux.HandleFunc("/admin/api/tokens/verify", a.requireAuth(a.handleTokenVerify))
	mux.HandleFunc("/admin/api/models", a.requireAuth(a.handleModels))
	mux.HandleFunc("/admin/api/stats", a.requireAuth(a.handleStats))
	mux.HandleFunc("/admin/api/logs", a.requireAuth(a.handleLogs))
	mux.HandleFunc("/admin/api/config", a.requireAuth(a.handleConfig))
	mux.HandleFunc("/admin/api/password", a.requireAuth(a.handlePassword))
}

// --- Session & Auth ---

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *Admin) createSession() (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}
	a.sessionMu.Lock()
	a.sessions[token] = time.Now().Add(sessionDuration)
	// Opportunistic cleanup: remove expired sessions
	now := time.Now()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.sessionMu.Unlock()
	return token, nil
}

func (a *Admin) isValidSession(token string) bool {
	if token == "" {
		return false
	}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	expiry, ok := a.sessions[token]
	if !ok || time.Now().After(expiry) {
		delete(a.sessions, token)
		return false
	}
	return true
}

func (a *Admin) removeSession(token string) {
	a.sessionMu.Lock()
	delete(a.sessions, token)
	a.sessionMu.Unlock()
}

func (a *Admin) getPassword() string {
	if env := os.Getenv("QODER_ADMIN_PASSWORD"); env != "" {
		return env
	}
	return a.store.GetPassword()
}

// --- Login rate limiting (per client IP, exponential backoff) ---

type loginAttempt struct {
	failures    int
	lockedUntil time.Time
	lastFail    time.Time
}

type loginLimiter struct {
	mu    sync.Mutex
	state map[string]*loginAttempt
}

const (
	loginMaxBackoff = 30 * time.Second
	loginPruneAge   = time.Hour
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{state: make(map[string]*loginAttempt)}
}

// check reports whether the IP is currently locked out and, if so, how long
// until it may retry.
func (l *loginLimiter) check(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked()
	st := l.state[ip]
	if st == nil {
		return false, 0
	}
	now := time.Now()
	if now.Before(st.lockedUntil) {
		return true, st.lockedUntil.Sub(now)
	}
	return false, 0
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.state[ip]
	if st == nil {
		st = &loginAttempt{}
		l.state[ip] = st
	}
	st.failures++
	st.lastFail = time.Now()
	// Compute the backoff in plain integers and clamp before converting to
	// time.Duration: 1<<63 seconds overflows int64 nanoseconds and yields a
	// negative duration, which would silently disable the lockout after
	// enough consecutive failures.
	shift := st.failures - 1
	if shift > 5 { // 1<<5 s == 32s > loginMaxBackoff
		shift = 5
	}
	backoff := time.Second << uint(shift)
	if backoff > loginMaxBackoff {
		backoff = loginMaxBackoff
	}
	st.lockedUntil = st.lastFail.Add(backoff)
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	delete(l.state, ip)
	l.mu.Unlock()
}

func (l *loginLimiter) pruneLocked() {
	cutoff := time.Now().Add(-loginPruneAge)
	for ip, st := range l.state {
		if st.lastFail.Before(cutoff) {
			delete(l.state, ip)
		}
	}
}

// --- Request helpers ---

// readJSON decodes a JSON request body capped at adminMaxBody. The size cap
// bounds memory use against oversized payloads.
func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxBody)
	return json.NewDecoder(r.Body).Decode(v)
}

// passwordsEqual compares two secrets in constant time to avoid timing leaks.
func passwordsEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	// Trim the port, handling both "1.2.3.4:5678" and "[::1]:5678".
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return host
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp == "https" {
		return true
	}
	return false
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		MaxAge:   int(sessionDuration.Seconds()),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
	})
}

// requireAuth wraps a handler with session authentication.
func (a *Admin) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_session")
		if err != nil || !a.isValidSession(cookie.Value) {
			writeJSONError(w, 401, "未登录或会话已过期")
			return
		}
		next(w, r)
	}
}

func (a *Admin) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	ip := clientIP(r)
	if locked, retry := a.limiter.check(ip); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeJSONError(w, 429, "登录尝试过于频繁，请稍后再试")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSONError(w, 400, "请求格式错误")
		return
	}
	if !passwordsEqual(body.Password, a.getPassword()) {
		a.limiter.fail(ip)
		writeJSONError(w, 401, "密码错误")
		return
	}
	a.limiter.success(ip)
	token, err := a.createSession()
	if err != nil {
		writeJSONError(w, 500, "无法创建会话")
		return
	}
	setSessionCookie(w, r, token)
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *Admin) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	if cookie, err := r.Cookie("admin_session"); err == nil {
		a.removeSession(cookie.Value)
	}
	clearSessionCookie(w, r)
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *Admin) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	cookie, err := r.Cookie("admin_session")
	authed := err == nil && a.isValidSession(cookie.Value)
	writeJSON(w, 200, map[string]interface{}{"authenticated": authed})
}

func (a *Admin) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSONError(w, 400, "请求格式错误")
		return
	}
	if os.Getenv("QODER_ADMIN_PASSWORD") != "" {
		writeJSONError(w, 400, "密码由环境变量 QODER_ADMIN_PASSWORD 管理，无法在面板中修改")
		return
	}
	if !passwordsEqual(body.CurrentPassword, a.getPassword()) {
		writeJSONError(w, 401, "当前密码错误")
		return
	}
	if len(body.NewPassword) < 1 {
		writeJSONError(w, 400, "新密码不能为空")
		return
	}
	if err := a.store.SetPassword(body.NewPassword); err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}
	// Invalidate every existing session so a (possibly stolen) cookie from
	// before the password change cannot be replayed.
	a.sessionMu.Lock()
	a.sessions = make(map[string]time.Time)
	a.sessionMu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// --- HTTP Helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- API Key endpoints ---

func (a *Admin) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := a.store.ListKeys()
		writeJSON(w, 200, map[string]interface{}{"keys": keys})
	case http.MethodPost:
		var body struct {
			Key  string `json:"key"`
			Note string `json:"note"`
		}
		if err := readJSON(w, r, &body); err != nil {
			writeJSONError(w, 400, "请求格式错误")
			return
		}
		entry, err := a.store.AddKey(body.Key, body.Note)
		if err != nil {
			if errors.Is(err, store.ErrDuplicateKey) {
				writeJSONError(w, 409, err.Error())
			} else {
				writeJSONError(w, 500, err.Error())
			}
			return
		}
		writeJSON(w, 201, entry)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSONError(w, 400, "缺少 id 参数")
			return
		}
		if err := a.store.DeleteKey(id); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	default:
		writeJSONError(w, 405, "方法不允许")
	}
}

// --- Config endpoint ---

// timeoutEnvManaged reports whether stream timeouts are pinned by env vars,
// in which case the panel must not override them (same policy as
// QODER_ADMIN_PASSWORD for password changes).
func timeoutEnvManaged() bool {
	return os.Getenv("QODER_CHAT_TIMEOUT_SECONDS") != "" ||
		os.Getenv("QODER_IDLE_TIMEOUT_SECONDS") != ""
}

// logLimitsEnvManaged reports whether the log limits are pinned by env vars,
// in which case the panel must not change them (same policy as the timeouts).
func logLimitsEnvManaged() bool {
	return os.Getenv("QODER_LOG_RETENTION_DAYS") != "" ||
		os.Getenv("QODER_LOG_MAX_ENTRIES") != ""
}

func (a *Admin) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Report effective values, not the persisted file values: env startup
		// overrides are already folded into the stream timeouts and into the
		// log limits held by the recorder.
		timeouts := auth.CurrentStreamTimeouts()
		retentionDays, maxEntries := a.store.GetLogRetentionDays(), a.store.GetLogMaxEntries()
		if a.logRec != nil {
			retentionDays, maxEntries = a.logRec.Limits()
		}
		writeJSON(w, 200, map[string]interface{}{
			"host":                 a.store.GetHost(),
			"port":                 a.store.GetPort(),
			"chat_timeout_seconds": int(timeouts.Header.Seconds()),
			"idle_timeout_seconds": int(timeouts.Idle.Seconds()),
			"log_retention_days":   retentionDays,
			"log_max_entries":      maxEntries,
		})
	case http.MethodPost:
		var body struct {
			Host               string `json:"host"`
			Port               int    `json:"port"`
			ChatTimeoutSeconds int    `json:"chat_timeout_seconds"`
			IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
			LogRetentionDays   int    `json:"log_retention_days"`
			LogMaxEntries      int    `json:"log_max_entries"`
		}
		if err := readJSON(w, r, &body); err != nil {
			writeJSONError(w, 400, "请求格式错误")
			return
		}
		if body.Host == "" {
			body.Host = store.DefaultHost
		}
		if body.Port == 0 {
			body.Port = store.DefaultPort
		}
		if body.Port < 1 || body.Port > 65535 {
			writeJSONError(w, 400, "端口必须在 1-65535 范围内")
			return
		}
		// Timeout fields are optional (0 = keep current) so legacy callers
		// that only send host/port keep working. Validate everything before
		// saving anything so a bad value cannot leave a partial update.
		wantsTimeouts := body.ChatTimeoutSeconds != 0 || body.IdleTimeoutSeconds != 0
		if wantsTimeouts && timeoutEnvManaged() {
			writeJSONError(w, 400, "超时由环境变量 QODER_CHAT_TIMEOUT_SECONDS / QODER_IDLE_TIMEOUT_SECONDS 管理，无法在面板中修改")
			return
		}
		if body.ChatTimeoutSeconds != 0 {
			if err := store.ValidateTimeoutSeconds(body.ChatTimeoutSeconds, store.MaxChatTimeoutSeconds); err != nil {
				writeJSONError(w, 400, "Chat 响应超时："+err.Error())
				return
			}
		}
		if body.IdleTimeoutSeconds != 0 {
			if err := store.ValidateTimeoutSeconds(body.IdleTimeoutSeconds, store.MaxIdleTimeoutSeconds); err != nil {
				writeJSONError(w, 400, "流空闲超时："+err.Error())
				return
			}
		}
		// Log limits share the timeout convention: 0 = keep current, and a
		// value pinned by env vars is rejected.
		wantsLogLimits := body.LogRetentionDays != 0 || body.LogMaxEntries != 0
		if wantsLogLimits && logLimitsEnvManaged() {
			writeJSONError(w, 400, "日志配置由环境变量 QODER_LOG_RETENTION_DAYS / QODER_LOG_MAX_ENTRIES 管理，无法在面板中修改")
			return
		}
		if body.LogRetentionDays != 0 {
			if err := store.ValidateLogRetentionDays(body.LogRetentionDays); err != nil {
				writeJSONError(w, 400, "日志保留天数："+err.Error())
				return
			}
		}
		if body.LogMaxEntries != 0 {
			if err := store.ValidateLogMaxEntries(body.LogMaxEntries); err != nil {
				writeJSONError(w, 400, "日志条数上限："+err.Error())
				return
			}
		}
		if err := a.store.SetHostPort(body.Host, body.Port); err != nil {
			writeJSONError(w, 500, err.Error())
			return
		}
		if body.ChatTimeoutSeconds != 0 {
			if err := a.store.SetChatTimeoutSeconds(body.ChatTimeoutSeconds); err != nil {
				writeJSONError(w, 500, err.Error())
				return
			}
		}
		if body.IdleTimeoutSeconds != 0 {
			if err := a.store.SetIdleTimeoutSeconds(body.IdleTimeoutSeconds); err != nil {
				writeJSONError(w, 500, err.Error())
				return
			}
		}
		if body.LogRetentionDays != 0 {
			if err := a.store.SetLogRetentionDays(body.LogRetentionDays); err != nil {
				writeJSONError(w, 500, err.Error())
				return
			}
		}
		if body.LogMaxEntries != 0 {
			if err := a.store.SetLogMaxEntries(body.LogMaxEntries); err != nil {
				writeJSONError(w, 500, err.Error())
				return
			}
		}
		// Hot-apply the log limits so a lowered cap prunes the live recorder at
		// once, not at the next request or flush.
		if wantsLogLimits && a.logRec != nil {
			a.logRec.SetLimits(a.store.GetLogRetentionDays(), a.store.GetLogMaxEntries())
		}
		// Hot-apply only when the request actually carried timeout fields:
		// re-applying store values unconditionally would clobber env-pinned
		// timeouts on a legacy host/port-only save.
		if wantsTimeouts {
			auth.SetStreamTimeouts(
				time.Duration(a.store.GetChatTimeoutSeconds())*time.Second,
				time.Duration(a.store.GetIdleTimeoutSeconds())*time.Second,
			)
		}
		timeouts := auth.CurrentStreamTimeouts()
		retentionDays, maxEntries := a.store.GetLogRetentionDays(), a.store.GetLogMaxEntries()
		if a.logRec != nil {
			retentionDays, maxEntries = a.logRec.Limits()
		}
		writeJSON(w, 200, map[string]interface{}{
			"host":                 body.Host,
			"port":                 body.Port,
			"chat_timeout_seconds": int(timeouts.Header.Seconds()),
			"idle_timeout_seconds": int(timeouts.Idle.Seconds()),
			"log_retention_days":   retentionDays,
			"log_max_entries":      maxEntries,
			"restart":              "修改主机或端口后需要重启服务才能生效（超时与日志配置已即时生效）",
		})
	default:
		writeJSONError(w, 405, "方法不允许")
	}
}

// --- Token pool endpoints ---

// TokenView is one pool account as the panel sees it: the masked credential and
// config weight, plus the live health verdict and allowance the bridge cached
// out of band. Building the view performs no upstream call.
type TokenView struct {
	ID        string `json:"id"`
	PATMasked string `json:"pat_masked"`
	Note      string `json:"note"`
	Weight    int    `json:"weight"`
	// Disabled is the operator switch: the account stays configured but is held
	// out of rotation by hand.
	Disabled  bool  `json:"disabled"`
	CreatedAt int64 `json:"created_at"`
	// State is the gateway's verdict, independent of the operator switch:
	// "healthy", "cooldown" (busy / rate-limited / exhausted), or "disabled"
	// (the credential itself was refused).
	State           string  `json:"state"`
	Reason          string  `json:"reason,omitempty"`
	CooldownUntilMs int64   `json:"cooldown_until_ms,omitempty"`
	Plan            string  `json:"plan,omitempty"`
	Tag             string  `json:"tag,omitempty"`
	OrgName         string  `json:"org_name,omitempty"`
	QuotaUsed       float64 `json:"quota_used"`
	QuotaTotal      float64 `json:"quota_total"`
	QuotaRemaining  float64 `json:"quota_remaining"`
	QuotaPercentage float64 `json:"quota_percentage"`
	QuotaUnit       string  `json:"quota_unit,omitempty"`
	// HasQuota distinguishes an account whose allowance is genuinely 0 from one
	// the account services have never reported for yet.
	HasQuota        bool  `json:"has_quota"`
	IsQuotaExceeded bool  `json:"is_quota_exceeded"`
	NextResetAtMs   int64 `json:"next_reset_at_ms,omitempty"`
}

// tokenViews pairs the stored config with the pool's live state. An account the
// pool has not reconciled yet still appears (state "healthy"), because the
// operator needs to see and edit it either way.
func (a *Admin) tokenViews() []TokenView {
	tokens := a.store.ListTokens()
	views := make([]TokenView, 0, len(tokens))
	for _, t := range tokens {
		v := TokenView{
			ID: t.ID, PATMasked: maskPAT(t.PAT), Note: t.Note,
			Weight: t.Weight, Disabled: t.Disabled, CreatedAt: t.CreatedAt,
			State: bridge.StateHealthy.String(),
		}
		if a.pool != nil {
			if e := a.pool.Find(t.ID); e != nil {
				st := e.Status()
				v.State = st.State.String()
				v.Reason = st.Reason
				v.CooldownUntilMs = st.CooldownUntilMs
			}
		}
		if acc := a.accountOf(t.ID); acc != nil {
			v.Plan, v.Tag, v.OrgName = acc.Plan, acc.UserTag, acc.OrgName
			v.IsQuotaExceeded = acc.IsQuotaExceeded
			v.NextResetAtMs = acc.NextResetAtMs
			if q := acc.UserQuota; q != nil {
				v.HasQuota = true
				v.QuotaUsed, v.QuotaTotal, v.QuotaRemaining = q.Used, q.Total, q.Remaining
				v.QuotaPercentage, v.QuotaUnit = q.Percentage, q.Unit
			}
		}
		views = append(views, v)
	}
	return views
}

// accountOf returns the cached subscription snapshot of one pool account, or nil
// when the account loop has not fetched it yet. It never reaches the gateway.
func (a *Admin) accountOf(id string) *auth.AccountStatus {
	if a.pool == nil {
		return nil
	}
	e := a.pool.Find(id)
	if e == nil {
		return nil
	}
	b := e.Bridge()
	if b == nil {
		return nil
	}
	return b.AccountStatus()
}

func (a *Admin) handleTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		views := a.tokenViews()
		available := 0
		if a.pool != nil {
			available = a.pool.Available()
		}
		writeJSON(w, 200, map[string]interface{}{
			// total is the configured count (the store is its source); available
			// is the pool's live verdict on how many of them may take traffic.
			"tokens": views, "total": len(views), "available": available,
		})
	case http.MethodPost:
		a.addToken(w, r)
	case http.MethodPut:
		a.patchToken(w, r)
	case http.MethodDelete:
		a.deleteToken(w, r)
	default:
		writeJSONError(w, 405, "方法不允许")
	}
}

// addToken validates the credential with the gateway *before* persisting it. A
// PAT that cannot open a session would otherwise sit in the pool, get picked by
// the round-robin, and cost the client a failed account rotation.
func (a *Admin) addToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PAT    string `json:"pat"`
		Note   string `json:"note"`
		Weight int    `json:"weight"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSONError(w, 400, "请求格式错误")
		return
	}
	pat := strings.TrimSpace(body.PAT)
	if pat == "" {
		writeJSONError(w, 400, "令牌不能为空")
		return
	}
	if body.Weight == 0 {
		body.Weight = store.DefaultTokenWeight
	}
	if err := store.ValidateTokenWeight(body.Weight); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	// Reject a duplicate from the stored config rather than from the pool: the
	// pool may lag the file, and the operator must not pay for a verification
	// round trip to learn the account is already there.
	for _, t := range a.store.ListTokens() {
		if t.PAT == pat {
			writeJSONError(w, 409, "该令牌已在池中")
			return
		}
	}
	st, err := a.verifyPAT(r.Context(), pat)
	if err != nil {
		writeJSONError(w, 400, "令牌校验失败，未保存："+err.Error())
		return
	}
	tok, err := a.store.AddToken(pat, body.Note, body.Weight)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrDuplicateToken):
			writeJSONError(w, 409, "该令牌已在池中")
		default:
			writeJSONError(w, 500, err.Error())
		}
		return
	}
	resp := map[string]interface{}{"status": "added", "token": tokView(*tok)}
	if st != nil {
		resp["plan"] = st.Plan
		resp["tag"] = st.UserTag
	}
	writeJSON(w, 201, resp)
}

// patchToken updates note / weight / the operator switch. The credential itself
// is not editable: replacing a PAT means removing the account and adding the new
// one, which is also what keeps the health verdict honest.
func (a *Admin) patchToken(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSONError(w, 400, "缺少 id 参数")
		return
	}
	var body struct {
		Note     *string `json:"note"`
		Weight   *int    `json:"weight"`
		Disabled *bool   `json:"disabled"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSONError(w, 400, "请求格式错误")
		return
	}
	// Validate everything before writing anything: a rejected weight must not
	// leave the note silently updated.
	if body.Weight != nil {
		if err := store.ValidateTokenWeight(*body.Weight); err != nil {
			writeJSONError(w, 400, err.Error())
			return
		}
	}
	if err := a.store.PatchToken(id, store.TokenPatch{Note: body.Note, Weight: body.Weight, Disabled: body.Disabled}); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSONError(w, 404, "令牌不存在")
			return
		}
		writeJSONError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *Admin) deleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSONError(w, 400, "缺少 id 参数")
		return
	}
	if err := a.store.DeleteToken(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSONError(w, 404, "令牌不存在")
			return
		}
		writeJSONError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// handleTokenVerify re-checks one configured credential against the gateway and
// installs the verdict on the pool entry. It is how a token that was disabled by
// a transient auth outage comes back without being re-entered.
func (a *Admin) handleTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	id := r.URL.Query().Get("id")
	tok, ok := a.store.GetToken(id)
	if !ok {
		writeJSONError(w, 404, "令牌不存在")
		return
	}
	st, err := a.verifyPAT(r.Context(), tok.PAT)
	if err != nil {
		if e := a.poolEntry(id); e != nil {
			e.MarkRejected("网关拒绝该令牌：" + err.Error())
		}
		writeJSONError(w, 400, "令牌校验失败："+err.Error())
		return
	}
	if e := a.poolEntry(id); e != nil {
		e.MarkVerified()
	}
	resp := map[string]interface{}{"status": "ok"}
	if st != nil {
		resp["plan"], resp["tag"] = st.Plan, st.UserTag
	}
	writeJSON(w, 200, resp)
}

func (a *Admin) poolEntry(id string) *bridge.PoolEntry {
	if a.pool == nil {
		return nil
	}
	return a.pool.Find(id)
}

// tokView renders a stored token with no live state attached — the shape the
// add response returns before the account loop has fetched anything.
func tokView(t store.Token) TokenView {
	return TokenView{
		ID: t.ID, PATMasked: maskPAT(t.PAT), Note: t.Note, Weight: t.Weight,
		Disabled: t.Disabled, CreatedAt: t.CreatedAt, State: bridge.StateHealthy.String(),
	}
}

// --- Models endpoint ---

func (a *Admin) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	var modelList []string
	if a.modelFetcher != nil {
		modelList = a.modelFetcher(r.Context())
	}
	if modelList == nil {
		catalog := models.DefaultCatalog()
		modelList = catalog.Keys()
	}
	writeJSON(w, 200, map[string]interface{}{"models": modelList})
}

// --- Stats endpoint ---

func (a *Admin) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	if a.stats == nil {
		writeJSON(w, 200, stats.Report{})
		return
	}
	writeJSON(w, 200, a.stats.Report())
}

// --- Logs endpoint ---

// handleLogs serves GET /admin/api/logs: a paginated, filterable request log.
// Query params: model (substring), key_id (exact), status ("error" or a code),
// page, page_size.
func (a *Admin) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "方法不允许")
		return
	}
	if a.logRec == nil {
		writeJSON(w, 200, logs.Result{Logs: []logs.LogEntry{}})
		return
	}
	q := r.URL.Query()
	f := logs.Filter{
		Model:    strings.TrimSpace(q.Get("model")),
		KeyID:    strings.TrimSpace(q.Get("key_id")),
		Page:     atoiDefault(q.Get("page"), 1),
		PageSize: atoiDefault(q.Get("page_size"), 20),
	}
	switch v := q.Get("status"); v {
	case "error":
		f.Status = -1
	case "":
		// no status filter
	default:
		if n, err := strconv.Atoi(v); err == nil {
			f.Status = n
		}
	}
	writeJSON(w, 200, a.logRec.Query(f))
}

// atoiDefault parses s as an int, falling back to def when empty or invalid.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// maskPAT returns a masked version of the PAT for display. It slices by rune: a
// note-free PAT is ASCII in practice, but a hand-edited value with multi-byte
// characters must not come back as invalid UTF-8 (which JSON encoders turn into
// U+FFFD and the browser renders as garbage).
func maskPAT(pat string) string {
	r := []rune(pat)
	if len(r) == 0 {
		return ""
	}
	if len(r) <= 8 {
		return "****"
	}
	return string(r[:4]) + "****" + string(r[len(r)-4:])
}
