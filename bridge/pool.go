// Multi-account token pool: smooth weighted round-robin selection over the
// configured PATs, health states driven only by facts the gateway reported, and
// account failover that stays inside the "nothing has reached the client yet"
// boundary.
package bridge

import (
	"context"
	"errors"
	"log"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"qoder2api/auth"
	"qoder2api/logs"
	"qoder2api/models"
)

// TokenConfig is one pool entry as the bridge side needs to know it. It mirrors
// store.Token so the pool stays independent of the persistence layer.
type TokenConfig struct {
	ID       string
	PAT      string
	Note     string
	Weight   int
	Disabled bool
}

// ConfigSource reports the current pool config together with a mutation
// generation. The pool reconciles only when the generation changes, so the
// secret-bearing config is read on config edits rather than per request.
type ConfigSource func() (tokens []TokenConfig, gen int64)

// AccountState is the pool's verdict on whether an account may take traffic.
type AccountState int

const (
	StateHealthy AccountState = iota
	// StateCooldown skips the account for a bounded time: quota exhausted,
	// gateway busy, or a rate-limit signal.
	StateCooldown
	// StateDisabled means the gateway rejected the credential itself. Only an
	// operator action (a successful re-verify) clears it.
	StateDisabled
)

func (s AccountState) String() string {
	switch s {
	case StateCooldown:
		return "cooldown"
	case StateDisabled:
		return "disabled"
	default:
		return "healthy"
	}
}

const (
	// maxAccountAttempts bounds how many accounts one client request may touch.
	// Beyond three, a pool-wide outage costs the client seconds of pointless
	// upstream attempts instead of one clear error.
	maxAccountAttempts = 3
	// maxCooldown caps a gateway-suggested avoidance window. A retry-after of
	// many minutes would take the account out of rotation for longer than the
	// operator can see why.
	maxCooldown = 30 * time.Second
	// quotaCooldown is the avoidance window for an exhausted account whose
	// gateway response carries no plausible reset boundary.
	quotaCooldown = time.Minute
)

// --- PoolEntry ---

// PoolEntry pairs one PAT with its bridge, weight and health state. The bridge
// owns the session, concurrency slots, catalog and quota snapshot of that one
// account, so entries never share a queue or a credential.
type PoolEntry struct {
	ID string

	mu     sync.Mutex
	note   string
	weight int
	off    bool // operator switch from the config
	pat    string
	bridge *OpenAiBridge
	state  AccountState
	until  time.Time
	reason string
	// admission marks a cooldown that came from the gateway's admission control
	// (busy / rate-limited) rather than from an exhausted allowance. That wait is
	// worth handing to the client as Retry-After; waiting out a billing cycle
	// is not, and must not invite immediate retries.
	admission bool
	served    int64
	failures  int64
}

// applyConfig installs a config version of this entry. A PAT change rebuilds the
// bridge (new session, new slots) and clears any health verdict recorded against
// the old credential.
func (e *PoolEntry) applyConfig(tc TokenConfig, newBridge func(pat string) *OpenAiBridge) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.note, e.weight, e.off = tc.Note, tc.Weight, tc.Disabled
	if e.pat != tc.PAT {
		e.pat = tc.PAT
		e.bridge = newBridge(tc.PAT)
		e.state = StateHealthy
		e.until = time.Time{}
		e.reason = ""
	}
}

// Bridge returns the entry's bridge (nil only before the first config sync).
func (e *PoolEntry) Bridge() *OpenAiBridge {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bridge
}

// Note returns the operator label of the account.
func (e *PoolEntry) Note() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.note
}

// eligibleWeight reports whether the account may take traffic now, together
// with its weight, and advances the health state along the way: a cooldown that
// has run out returns the account to rotation, and the cached quota snapshot
// (the gateway's own verdict, fetched out of band) takes an exhausted account
// out until the boundary the gateway reported.
func (e *PoolEntry) eligibleWeight(now time.Time) (bool, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.off {
		return false, e.weight
	}
	switch e.state {
	case StateDisabled:
		return false, e.weight
	case StateCooldown:
		if now.Before(e.until) {
			return false, e.weight
		}
		e.state = StateHealthy
		e.until = time.Time{}
		e.reason = ""
		e.admission = false
	}
	if e.bridge != nil {
		if st := e.bridge.AccountStatus(); st != nil && st.IsQuotaExceeded {
			e.state = StateCooldown
			e.reason = "额度已用尽"
			// An exhausted allowance is not an admission signal: the wait is a
			// billing cycle away, so the client must not get a Retry-After for it.
			e.admission = false
			if plausibleResetMs(st.NextResetAtMs) {
				e.until = time.UnixMilli(st.NextResetAtMs)
			} else {
				e.until = now.Add(quotaCooldown)
			}
			return false, e.weight
		}
	}
	return true, e.weight
}

func (e *PoolEntry) enterCooldown(now time.Time, after time.Duration, reason string) {
	if after <= 0 || after > maxCooldown {
		after = busyFallbackBackoff
	}
	e.state = StateCooldown
	e.until = now.Add(after)
	e.reason = reason
	e.admission = true
}

// observeFailure records what the gateway said about this account and reports
// whether a different account may be tried for the same client request.
//
// Only gateway facts move an account out of rotation: a rejected credential
// disables it, a busy or rate-limited answer cools it for the window the
// gateway asked for. Anything else — a 5xx provider fault, a transport error —
// leaves the state alone, because the account is not at fault, while still
// permitting one more try elsewhere. A 4xx rejection of the request body itself
// never fails over: every account would reject the same payload.
func (e *PoolEntry) observeFailure(err error) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	e.failures++

	// A client that hung up or a deadline that expired says nothing about the
	// account and must not spend another upstream try.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var authErr *auth.AuthError
	if errors.As(err, &authErr) {
		// openStreamAsync already refreshed and retried once before giving up,
		// so a remaining rejection is about the credential, not the session.
		e.state = StateDisabled
		e.until = time.Time{}
		e.reason = "网关拒绝该令牌：" + authErr.Error()
		log.Printf("[pool] account %s disabled: %v", e.ID, authErr)
		return true
	}

	var busyErr *auth.BusyError
	if errors.As(err, &busyErr) {
		e.enterCooldown(now, busyErr.RetryAfter, "网关繁忙")
		log.Printf("[pool] account %s cooling down: %v", e.ID, busyErr)
		return true
	}

	var upErr *auth.UpstreamError
	if errors.As(err, &upErr) {
		switch {
		case upErr.StatusCode == http.StatusTooManyRequests:
			e.enterCooldown(now, upErr.RetryAfter, "网关限流")
			return true
		case upErr.StatusCode >= 500 || upErr.StatusCode <= 0:
			return true
		default:
			return false
		}
	}

	var inErr *auth.InStreamError
	if errors.As(err, &inErr) {
		switch {
		case inErr.Status == http.StatusTooManyRequests:
			e.enterCooldown(now, 0, "网关限流")
			return true
		case inErr.Status >= 500 || inErr.Status <= 0:
			return true
		default:
			return false
		}
	}

	// The account's catalog cannot serve this model: a routing miss, not a
	// fault. Another account may well serve it.
	var unsupErr *models.UnsupportedModelError
	var capErr *models.CapabilityError
	if errors.As(err, &unsupErr) || errors.As(err, &capErr) {
		return true
	}

	// Transport failures and anything unclassified: try another account, but do
	// not blame this one.
	return true
}

// markServed clears a cooldown after a success. A disabled account can never
// have been picked, so the disabled verdict is left untouched.
func (e *PoolEntry) markServed() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.served++
	if e.state == StateCooldown {
		e.state = StateHealthy
		e.until = time.Time{}
		e.reason = ""
		e.admission = false
	}
}

// setHealth overrides the health verdict. The admin verify action uses it: a
// credential the gateway accepts must leave the disabled state immediately.
func (e *PoolEntry) setHealth(state AccountState, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = state
	e.until = time.Time{}
	e.reason = reason
}

// MarkVerified installs a successful upstream check: any cooldown or disabled
// verdict recorded against this credential is dropped and the account returns to
// rotation.
func (e *PoolEntry) MarkVerified() { e.setHealth(StateHealthy, "") }

// MarkRejected records a credential the gateway refused, with the check's own
// wording as the panel reason.
func (e *PoolEntry) MarkRejected(reason string) { e.setHealth(StateDisabled, reason) }

// EntryStatus is the admin-facing view of one account.
type EntryStatus struct {
	State           AccountState
	Reason          string
	CooldownUntilMs int64
	// Off is the operator switch: the account is configured but held out of
	// rotation by hand, not by a gateway verdict.
	Off     bool
	Weight  int
	Note    string
	Account *auth.AccountStatus
}

func (e *PoolEntry) Status() EntryStatus {
	e.mu.Lock()
	st := EntryStatus{
		State:  e.state,
		Reason: e.reason,
		Off:    e.off,
		Weight: e.weight,
		Note:   e.note,
	}
	if !e.until.IsZero() {
		st.CooldownUntilMs = e.until.UnixMilli()
	}
	b := e.bridge
	e.mu.Unlock()
	if b != nil {
		st.Account = b.AccountStatus()
	}
	return st
}

// --- Pool ---

// Pool selects among the configured accounts and runs one request against
// them, failing over while the response is still uncommitted.
type Pool struct {
	config    ConfigSource
	newBridge func(pat string) *OpenAiBridge

	mu      sync.Mutex
	entries []*PoolEntry
	byID    map[string]*PoolEntry
	gen     int64
	cur     map[string]int64 // smooth weighted round-robin cursors
}

// NewPool creates a pool fed by src. Bridges are minted on the first sync and
// whenever a PAT changes.
func NewPool(src ConfigSource) *Pool {
	return &Pool{
		config: src,
		newBridge: func(pat string) *OpenAiBridge {
			realPAT, region := auth.Resolve(pat)
			return NewOpenAiBridge(realPAT, region)
		},
		byID: make(map[string]*PoolEntry),
		cur:  make(map[string]int64),
	}
}

// Sync reconciles the entries with the config. Per-entry health survives an
// edit (re-weighting one account must not cool down its neighbours) and entries
// the config no longer lists are dropped.
func (p *Pool) Sync() {
	tokens, gen := p.config()
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen == p.gen && p.entries != nil {
		return
	}
	next := make([]*PoolEntry, 0, len(tokens))
	seen := make(map[string]bool, len(tokens))
	for _, tc := range tokens {
		if tc.ID == "" || seen[tc.ID] {
			continue
		}
		seen[tc.ID] = true
		e := p.byID[tc.ID]
		if e == nil {
			e = &PoolEntry{ID: tc.ID}
		}
		e.applyConfig(tc, p.newBridge)
		next = append(next, e)
	}
	p.entries = next
	p.byID = make(map[string]*PoolEntry, len(next))
	// Cursors are rebuilt with the entry set: a stale cursor from a removed
	// account would skew the first picks after the edit.
	p.cur = make(map[string]int64, len(next))
	for _, e := range next {
		p.byID[e.ID] = e
	}
	p.gen = gen
}

// Entries returns the current entries in config order.
func (p *Pool) Entries() []*PoolEntry {
	p.Sync()
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*PoolEntry(nil), p.entries...)
}

// Len reports how many accounts are configured.
func (p *Pool) Len() int {
	p.Sync()
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// Available reports how many accounts may take traffic right now.
func (p *Pool) Available() int {
	p.Sync()
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.entries {
		if ok, _ := e.eligibleWeight(now); ok {
			n++
		}
	}
	return n
}

// Find returns the entry carrying this config id, or nil when the pool does not
// list it. The pool reconciles from the store on access, so a token added
// moments ago is already present here.
func (p *Pool) Find(id string) *PoolEntry {
	if id == "" {
		return nil
	}
	for _, e := range p.Entries() {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// LabelBridge is the bridge used to resolve a default model name for the
// statistics label when the client omitted "model". Any account will do — they
// share the same catalog scene in practice — so the first eligible one wins.
func (p *Pool) LabelBridge() *OpenAiBridge {
	now := time.Now()
	for _, e := range p.Entries() {
		b := e.Bridge()
		if b == nil {
			continue
		}
		if ok, _ := e.eligibleWeight(now); ok {
			return b
		}
	}
	for _, e := range p.Entries() {
		if b := e.Bridge(); b != nil {
			return b
		}
	}
	return nil
}

// pickLocked advances one smooth weighted round-robin step over the eligible,
// not-yet-tried accounts and returns the winner, or nil when none may take
// traffic.
func (p *Pool) pickLocked(tried map[string]bool, now time.Time) *PoolEntry {
	if e := p.pickEligibleLocked(tried, now); e != nil {
		return e
	}
	return p.pickLastResortLocked(tried, now)
}

func (p *Pool) pickEligibleLocked(tried map[string]bool, now time.Time) *PoolEntry {
	var best *PoolEntry
	var total int64
	for _, e := range p.entries {
		if tried[e.ID] {
			continue
		}
		ok, w := e.eligibleWeight(now)
		if !ok {
			continue
		}
		if w < 1 {
			w = 1
		}
		p.cur[e.ID] += int64(w)
		total += int64(w)
		if best == nil || p.cur[e.ID] > p.cur[best.ID] {
			best = e
		}
	}
	if best == nil {
		return nil
	}
	p.cur[best.ID] -= total
	return best
}

// pickLastResortLocked handles the case a cooldown cannot be routed around: when
// exactly one account is left that the operator has not switched off and the
// gateway has not rejected as a credential, its cooldown has no healthy peer to
// hide behind, so the request goes to it anyway.
//
// This keeps a single-token deployment behaving the way it did before the pool
// existed (the bridge's own slot queue and busy back-off still apply), while a
// pool with several usable accounts never lands here: those requests go to a
// healthy peer, or come back to the client as a retry-later.
func (p *Pool) pickLastResortLocked(tried map[string]bool, now time.Time) *PoolEntry {
	var sole *PoolEntry
	for _, e := range p.entries {
		e.mu.Lock()
		usable := !e.off && e.state != StateDisabled
		e.mu.Unlock()
		if !usable {
			continue
		}
		if sole != nil {
			return nil
		}
		sole = e
	}
	if sole == nil || tried[sole.ID] {
		return nil
	}
	// Run the state machine once so a cooldown that has already expired returns
	// the account to rotation instead of staying marked.
	sole.eligibleWeight(now)
	return sole
}

// NoAccountError means the pool holds no account that may serve this request:
// nothing configured, or every account is cooled down or disabled. It is a
// capacity problem, not a client error.
//
// RetryAfter carries the earliest moment one of the cooling accounts may come
// back, but only when that wait came from the gateway's own admission control
// (busy / rate-limited). The handler turns it into a 429 with Retry-After: a
// single-account pool whose gateway is busy must answer the next client with the
// backoff the gateway asked for, not with a bare 503 that invites immediate
// retries onto the same busy account.
type NoAccountError struct {
	Total      int
	RetryAfter time.Duration
}

func (e *NoAccountError) Error() string {
	if e.Total == 0 {
		return "尚未配置访问令牌，请在令牌页添加账号"
	}
	if e.RetryAfter > 0 {
		return "令牌池内 " + strconv.Itoa(e.Total) + " 个账号均在冷却，约 " +
			strconv.Itoa(int(math.Ceil(e.RetryAfter.Seconds()))) + " 秒后可重试"
	}
	return "令牌池内没有可用账号（共 " + strconv.Itoa(e.Total) + " 个，均在冷却或停用中）"
}

// retryHintLocked is the shortest wait among accounts the gateway asked us to
// back off from. An exhausted allowance or a rejected credential is excluded on
// purpose: those waits are a billing cycle or an operator action away, and
// telling a client to retry in three weeks is not a rate limit.
func (p *Pool) retryHintLocked(now time.Time) time.Duration {
	var best time.Duration
	for _, e := range p.entries {
		e.mu.Lock()
		wait, admission := time.Duration(0), false
		if e.state == StateCooldown && e.admission && e.until.After(now) {
			wait, admission = e.until.Sub(now), true
		}
		e.mu.Unlock()
		if admission && (best == 0 || wait < best) {
			best = wait
		}
	}
	return best
}

// Do runs the request against the pool. It retries on another account only
// while nothing has been written to the client: once the first byte is out the
// response is committed, and replaying it would double-bill an account and
// splice two generations into one stream.
func (p *Pool) Do(ctx context.Context, w http.ResponseWriter, reqBody map[string]interface{}, usageSink UsageSink) ([]logs.Attempt, error) {
	p.Sync()
	var attempts []logs.Attempt
	var lastErr error
	tried := make(map[string]bool, maxAccountAttempts)

	for {
		now := time.Now()
		p.mu.Lock()
		total := len(p.entries)
		e := p.pickLocked(tried, now)
		hint := time.Duration(0)
		if e == nil {
			hint = p.retryHintLocked(now)
		}
		p.mu.Unlock()

		if e == nil {
			if lastErr != nil {
				// Every remaining account is out of rotation. The last upstream
				// answer is the most specific thing to report.
				return attempts, lastErr
			}
			return attempts, &NoAccountError{Total: total, RetryAfter: hint}
		}

		cw := &commitWriter{ResponseWriter: w}
		start := time.Now()
		err := e.Bridge().HandleChat(ctx, cw, reqBody, usageSink)
		attempts = append(attempts, logs.Attempt{
			TokenID:    e.ID,
			Note:       e.Note(),
			OK:         err == nil,
			Error:      errLabel(err),
			DurationMs: time.Since(start).Milliseconds(),
		})
		tried[e.ID] = true

		if err == nil {
			e.markServed()
			return attempts, nil
		}
		lastErr = err
		// Committed: the client already has bytes. Report the failure in place.
		if cw.committed {
			return attempts, err
		}
		if len(attempts) >= maxAccountAttempts || !e.observeFailure(err) {
			return attempts, err
		}
		log.Printf("[pool] account %s failed before any content (%v); trying the next account", e.ID, err)
	}
}

func errLabel(err error) string {
	if err == nil {
		return ""
	}
	return truncateRunes(err.Error(), 500)
}

// --- Models ---

// Models returns the union of every configured account's catalog. A model only
// some accounts can serve stays listed: the request path routes it to an account
// that has it, and only reports a 400 when no account does.
func (p *Pool) Models(ctx context.Context) *models.ModelCatalog {
	merged := &models.ModelCatalog{
		ModelMap:     make(map[string]string),
		VisionModels: make(map[string]bool),
		Caps:         make(map[string]*models.ModelCaps),
	}
	for _, e := range p.Entries() {
		b := e.Bridge()
		if b == nil {
			continue
		}
		cat := b.GetCatalog(ctx)
		for name, key := range cat.ModelMap {
			merged.ModelMap[name] = key
		}
		for name, ok := range cat.VisionModels {
			if ok {
				merged.VisionModels[name] = true
			}
		}
		for key, caps := range cat.Caps {
			if _, dup := merged.Caps[key]; !dup {
				merged.Caps[key] = caps
			}
		}
		if merged.DefaultName == "" || merged.DefaultName == cat.DefaultName {
			merged.DefaultName = cat.DefaultName
		}
	}
	if len(merged.ModelMap) == 0 {
		return models.DefaultCatalog()
	}
	return merged
}

// --- Verify ---

// verifyTimeout bounds a credential check started from the admin panel: the
// operator is waiting on a synchronous request that performs a jobToken
// exchange plus two account lookups, so it must stay under the browser's
// patience while remaining long enough for a healthy gateway round trip.
var verifyTimeout = 20 * time.Second

// VerifyPAT performs the cold jobToken exchange for pat on a throwaway bridge
// and returns that account's identity and allowance snapshot, or nil when the
// session opened but the account services were unreachable.
//
// Nothing is persisted and no pool entry is touched: the admin add-flow uses
// this as the gate in front of the store, so a credential the gateway rejects
// never enters the pool (and never spends a request slot on a broken account).
func VerifyPAT(ctx context.Context, pat string) (*auth.AccountStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	realPAT, region := auth.Resolve(pat)
	b := NewOpenAiBridge(realPAT, region)
	if err := b.EnsureFreshSession(ctx); err != nil {
		return nil, err
	}
	return b.EnsureAccountStatus(ctx), nil
}

// --- commitWriter ---

// commitWriter marks the moment a response stops being replayable. Header-only
// mutations (Content-Type on an SSE stream) commit nothing: Go writes the status
// line lazily, on the first byte of body. That makes this flag exactly the
// boundary the failover rule needs.
type commitWriter struct {
	http.ResponseWriter
	committed bool
}

func (c *commitWriter) Write(p []byte) (int, error) {
	c.committed = true
	return c.ResponseWriter.Write(p)
}

func (c *commitWriter) WriteHeader(status int) {
	c.committed = true
	c.ResponseWriter.WriteHeader(status)
}

// Flush must stay visible: handleStream type-asserts the writer to http.Flusher
// and would silently stop streaming through a wrapper that hides it.
func (c *commitWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *commitWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }
