package bridge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"qoder2api/auth"
	"qoder2api/logs"
	"qoder2api/models"
)

// --- Selection helpers ---

// pick runs one smooth weighted round-robin step over the whole pool the way Do
// does between client requests (no account tried yet).
func (p *Pool) pick() *PoolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pickEligibleLocked(nil, time.Now())
}

// pickN picks n times and returns the winners' IDs.
func (p *Pool) pickN(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if e := p.pick(); e != nil {
			out = append(out, e.ID)
		}
	}
	return out
}

// poolOfEntries assembles a pool from entries the test owns, with the same
// no-op config as newTestPool so Sync cannot rebuild over them.
func poolOfEntries(entries ...*PoolEntry) *Pool {
	p := &Pool{
		byID: make(map[string]*PoolEntry, len(entries)),
		cur:  make(map[string]int64, len(entries)),
		gen:  1,
	}
	p.config = func() ([]TokenConfig, int64) { return nil, 1 }
	for _, e := range entries {
		p.entries = append(p.entries, e)
		p.byID[e.ID] = e
	}
	return p
}

// forceCooldown installs a cooldown verdict without going through the gateway
// error it would normally come from, so a test controls the exact deadline.
func forceCooldown(e *PoolEntry, until time.Time, reason string, admission bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = StateCooldown
	e.until = until
	e.reason = reason
	e.admission = admission
}

// nginx's own worked example: weights 5/3/1 must give 5/3/1 over nine picks while
// interleaving them, so a heavier account gets its share without ever monopolising
// a run of requests.
func TestPoolSmoothWeightedRoundRobin(t *testing.T) {
	p := newTestPool(
		testAccount{id: "a", weight: 5},
		testAccount{id: "b", weight: 3},
		testAccount{id: "c", weight: 1},
	)
	got := p.pickN(9)
	counts := map[string]int{}
	for _, id := range got {
		counts[id]++
	}
	if counts["a"] != 5 || counts["b"] != 3 || counts["c"] != 1 {
		t.Fatalf("nine picks over weights 5/3/1 gave %+v (%v), want 5/3/1", counts, got)
	}
	for i := 2; i < len(got); i++ {
		if got[i] == got[i-1] && got[i] == got[i-2] {
			t.Errorf("one account ran three requests in a row (%v): rotation is not smooth", got)
			break
		}
	}
}

// An account the operator switched off, one the gateway rejected and one cooling
// down all stay out of rotation while a healthy peer exists.
func TestPoolExcludesUnusableAccounts(t *testing.T) {
	healthy := &PoolEntry{ID: "healthy", weight: 1, state: StateHealthy}
	off := &PoolEntry{ID: "off", weight: 1, state: StateHealthy, off: true}
	rejected := &PoolEntry{ID: "rejected", weight: 1, state: StateHealthy}
	cooling := &PoolEntry{ID: "cooling", weight: 1, state: StateHealthy}
	rejected.MarkRejected("凭证已被网关拒绝")
	forceCooldown(cooling, time.Now().Add(time.Minute), "网关繁忙", true)

	p := poolOfEntries(healthy, off, rejected, cooling)
	if got := p.Available(); got != 1 {
		t.Errorf("Available = %d, want 1", got)
	}
	for i := 0; i < 6; i++ {
		e := p.pick()
		if e == nil || e.ID != "healthy" {
			t.Fatalf("pick %d returned %v, want the only healthy account", i, e)
		}
	}
}

// A cooldown only degrades when a peer can absorb the request. With one account
// its own wait has nowhere to route around, so the request must still reach it:
// otherwise a single busy answer would turn a one-token deployment into a 503.
func TestPoolLastResortKeepsASoleCoolingAccount(t *testing.T) {
	sole := &PoolEntry{ID: "sole", weight: 1, state: StateHealthy}
	forceCooldown(sole, time.Now().Add(time.Minute), "网关繁忙", true)
	if ok, _ := sole.eligibleWeight(time.Now()); ok {
		t.Fatal("a cooling account must not be an eligible pick")
	}

	p := poolOfEntries(sole)
	e := p.pickAmong(map[string]bool{})
	if e == nil || e.ID != "sole" {
		t.Fatalf("last-resort pick = %v, want the sole cooling account", e)
	}
	// Once it has been tried, the same request must not loop back onto it.
	if e := p.pickAmong(map[string]bool{"sole": true}); e != nil {
		t.Errorf("the sole account came back for another attempt: %v", e)
	}
	// A rejected credential is never a last resort: it can only answer 401 again.
	rejected := &PoolEntry{ID: "dead", weight: 1, state: StateHealthy}
	rejected.MarkRejected("凭证已被网关拒绝")
	p2 := poolOfEntries(rejected)
	if e := p2.pickAmong(nil); e != nil {
		t.Errorf("a disabled account must not be served: %v", e)
	}
	// With a usable peer, the cooling account is skipped rather than forced.
	cooling := &PoolEntry{ID: "cooling", weight: 1, state: StateHealthy}
	forceCooldown(cooling, time.Now().Add(time.Minute), "网关繁忙", true)
	peer := &PoolEntry{ID: "peer", weight: 1, state: StateHealthy}
	p3 := poolOfEntries(cooling, peer)
	if got := p3.pickAmong(nil); got == nil || got.ID != "peer" {
		t.Errorf("with a healthy peer the pick must be it, got %v", got)
	}
}

// pickAmong runs one full selection step (eligible first, last resort after) with
// the pool lock held, the way Do does.
func (p *Pool) pickAmong(tried map[string]bool) *PoolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pickLocked(tried, time.Now())
}

// The health verdict comes only from what the gateway said: a rejected credential
// is permanent until re-verification, a busy answer is a bounded wait, a provider
// fault is not this account's fault, and a 4xx about the payload must not be paid
// for with another upstream attempt.
func TestPoolObserveFailure(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		failover bool
		state    AccountState
		reason   string
	}{
		{"rejected credential", &auth.AuthError{StatusCode: 401, Detail: "token expired"}, true, StateDisabled, "拒绝该令牌"},
		{"busy", &auth.BusyError{StatusCode: 403, Code: "10605", Message: "busy", RetryAfter: 2 * time.Second}, true, StateCooldown, "繁忙"},
		{"rate limited", &auth.UpstreamError{StatusCode: http.StatusTooManyRequests, Body: "slow down"}, true, StateCooldown, "限流"},
		{"provider fault", &auth.UpstreamError{StatusCode: 503, Body: "unavailable"}, true, StateHealthy, ""},
		{"payload rejected", &auth.UpstreamError{StatusCode: 400, Body: "bad temperature"}, false, StateHealthy, ""},
		{"unknown model", &models.UnsupportedModelError{Model: "x"}, true, StateHealthy, ""},
		{"unsupported capability", &models.CapabilityError{Model: "x"}, true, StateHealthy, ""},
		{"client hung up", context.Canceled, false, StateHealthy, ""},
		{"deadline exceeded", context.DeadlineExceeded, false, StateHealthy, ""},
		{"transport", errors.New("dial tcp: connection refused"), true, StateHealthy, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &PoolEntry{ID: "x", weight: 1, state: StateHealthy}
			if got := e.observeFailure(tc.err); got != tc.failover {
				t.Errorf("failover = %v, want %v", got, tc.failover)
			}
			if st := e.Status(); st.State != tc.state {
				t.Errorf("state = %v, want %v", st.State, tc.state)
			}
			if tc.reason != "" && !strings.Contains(e.Status().Reason, tc.reason) {
				t.Errorf("reason = %q, want it to mention %q", e.Status().Reason, tc.reason)
			}
		})
	}
}

// A success ends a cooldown — the gateway just served this credential, so the
// earlier back-off no longer applies. A disabled verdict never does: only an
// operator re-verification clears it.
func TestPoolMarkServedClearsCooldownOnly(t *testing.T) {
	cooling := &PoolEntry{ID: "a", weight: 1, state: StateHealthy}
	forceCooldown(cooling, time.Now().Add(time.Minute), "网关繁忙", true)
	cooling.markServed()
	if st := cooling.Status(); st.State != StateHealthy {
		t.Errorf("state after serving = %v, want healthy", st.State)
	}

	rejected := &PoolEntry{ID: "b", weight: 1, state: StateDisabled, reason: "凭证已被网关拒绝"}
	rejected.markServed()
	if st := rejected.Status(); st.State != StateDisabled {
		t.Errorf("a disabled account must not be revived implicitly, got %v", st.State)
	}
	rejected.MarkVerified()
	if st := rejected.Status(); st.State != StateHealthy || st.Reason != "" {
		t.Errorf("re-verification must return the account to rotation, got %+v", st)
	}
}

// An expired cooldown returns the account to rotation with no operator action.
func TestPoolCooldownExpires(t *testing.T) {
	e := &PoolEntry{ID: "a", weight: 1, state: StateHealthy}
	now := time.Now()
	forceCooldown(e, now.Add(time.Second), "网关繁忙", true)
	if ok, _ := e.eligibleWeight(now); ok {
		t.Fatal("expected to be inside the cooldown window")
	}
	if ok, _ := e.eligibleWeight(now.Add(2 * time.Second)); !ok {
		t.Error("an expired cooldown must leave the account eligible")
	}
	if st := e.Status(); st.State != StateHealthy {
		t.Errorf("state after expiry = %v, want healthy", st.State)
	}
}

// The gateway's own "out of allowance" verdict takes an account out of rotation
// until the boundary it reported, so the pool stops spending requests against an
// account that can only refuse them.
func TestPoolQuotaExhaustionCoolsDownUntilGatewayBoundary(t *testing.T) {
	b := newAccountBridge(t, &accountFixture{
		statusFunc: func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"id":"uid1","userType":"teams","plan":"PLAN_TIER_TEAM","userTag":"Teams","nextResetAt":1790265600000,"isQuotaExceeded":true}`)
		},
		quotaFunc: func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"userId":"uid1","userType":"teams","isQuotaExceeded":true,"userQuota":{"total":100,"used":100,"remaining":0,"unit":"credits"}}`)
		},
	})
	if st := b.EnsureAccountStatus(context.Background()); st == nil || !st.IsQuotaExceeded {
		t.Fatalf("test setup: expected an exhausted snapshot, got %+v", st)
	}

	e := &PoolEntry{ID: "a", weight: 1, state: StateHealthy, bridge: b}
	if ok, _ := e.eligibleWeight(time.Now()); ok {
		t.Fatal("an exhausted account must not be eligible")
	}
	st := e.Status()
	if st.State != StateCooldown {
		t.Errorf("state = %v, want cooldown", st.State)
	}
	if st.CooldownUntilMs != 1790265600000 {
		t.Errorf("cooldown until = %d, want the gateway boundary 1790265600000", st.CooldownUntilMs)
	}
	if !strings.Contains(st.Reason, "额度") {
		t.Errorf("reason = %q, want the quota wording", st.Reason)
	}

	// A billing-cycle wait is not an admission signal: telling the client to
	// retry in three weeks would only invite pointless retries.
	hint := poolOfEntries(e).retryHint()
	if hint != 0 {
		t.Errorf("retry hint = %v, want none for a billing-cycle wait", hint)
	}
}

// When nothing may serve, the wait the client is told is the shortest back-off
// the gateway actually asked for — a quota wait and an already-expired cooldown
// are both excluded.
func TestPoolRetryHintIsShortestAdmissionWait(t *testing.T) {
	now := time.Now()
	long := &PoolEntry{ID: "long", weight: 1, state: StateHealthy}
	forceCooldown(long, now.Add(9*time.Second), "网关繁忙", true)
	short := &PoolEntry{ID: "short", weight: 1, state: StateHealthy}
	forceCooldown(short, now.Add(3*time.Second), "网关限流", true)
	quota := &PoolEntry{ID: "quota", weight: 1, state: StateHealthy}
	forceCooldown(quota, now.Add(30*time.Second), "额度已用尽", false)
	stale := &PoolEntry{ID: "stale", weight: 1, state: StateHealthy}
	forceCooldown(stale, now.Add(-time.Second), "网关繁忙", true)

	hint := poolOfEntries(long, short, quota, stale).retryHintAt(now.Add(time.Second))
	if hint < 2*time.Second || hint > 3*time.Second {
		t.Errorf("retry hint = %v, want ~2s (the shortest admission wait minus the second already elapsed)", hint)
	}
}

func (p *Pool) retryHint() time.Duration {
	return p.retryHintAt(time.Now())
}

func (p *Pool) retryHintAt(now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.retryHintLocked(now)
}

// --- End-to-end behaviour over fake gateways ---

// Two accounts, the first credential rejected by the gateway: the client must get
// the second account's answer, and the trail must say both were touched.
func TestPoolFailsOverBeforeTheResponseIsCommitted(t *testing.T) {
	badGW := &fakeGateway{chatStatus: http.StatusUnauthorized}
	bad := newFakeBridge(t, badGW)
	goodGW := &fakeGateway{chatLines: okStream(t, "from-second")}
	good := newFakeBridge(t, goodGW)

	p := newTestPool(
		testAccount{id: "first", note: "A", bridge: bad},
		testAccount{id: "second", note: "B", bridge: good},
	)
	w := httptest.NewRecorder()
	attempts, err := p.Do(context.Background(), w, chatRequestBody("Fake-Model"), nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %+v, want the rejected account then the working one", attempts)
	}
	if attempts[0].TokenID != "first" || attempts[0].OK || attempts[0].Error == "" {
		t.Errorf("first attempt = %+v, want a failed one labelled with its cause", attempts[0])
	}
	if attempts[1].TokenID != "second" || !attempts[1].OK || attempts[1].Note != "B" {
		t.Errorf("second attempt = %+v", attempts[1])
	}
	if body := w.Body.String(); !strings.Contains(body, "from-second") {
		t.Errorf("client did not receive the failover account's answer:\n%s", body)
	}
	if st := p.Find("first").Status(); st.State != StateDisabled {
		t.Errorf("a credential the gateway refused should be disabled, got %v", st.State)
	}
	if st := p.Find("second").Status(); st.State != StateHealthy {
		t.Errorf("the serving account should be healthy, got %v", st.State)
	}
	if n := badGW.chatHits.Load(); n == 0 {
		t.Error("the first account was never actually contacted")
	}
}

// Once content reached the client the response is committed: replaying it on
// another account would bill twice and splice two generations into one stream.
func TestPoolNeverReplaysAfterCommittingContent(t *testing.T) {
	// A stream that delivers content and then dies without [DONE].
	partial := newFakeBridge(t, &fakeGateway{chatLines: []string{
		sseFrame(t, map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]interface{}{"content": "partial"}}}}),
	}})
	peerGW := &fakeGateway{chatLines: okStream(t, "should-not-run")}
	peer := newFakeBridge(t, peerGW)

	p := newTestPool(testAccount{id: "a", bridge: partial}, testAccount{id: "b", bridge: peer})
	w := httptest.NewRecorder()
	attempts, err := p.Do(context.Background(), w, chatRequestBody("Fake-Model"), nil)
	if err == nil {
		t.Fatal("expected the truncated stream to surface")
	}
	var repErr *StreamReportedError
	if !errors.As(err, &repErr) {
		t.Fatalf("expected an in-band reported error, got %T: %v", err, err)
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts = %+v, want exactly one: a committed response must not fail over", attempts)
	}
	if n := peerGW.chatHits.Load(); n != 0 {
		t.Errorf("the peer account was contacted %d times: the request was replayed", n)
	}
	body := w.Body.String()
	if !strings.Contains(body, "partial") || strings.Contains(body, "should-not-run") {
		t.Errorf("stream was spliced:\n%s", body)
	}
}

// A pool where every account is cooling down is capacity, not a server fault, and
// the client must be told the gateway's own wait.
func TestChatHandlerReportsPoolWideCooldownAs429(t *testing.T) {
	coolingA := &PoolEntry{ID: "a", weight: 1, note: "A", state: StateHealthy}
	coolingB := &PoolEntry{ID: "b", weight: 1, note: "B", state: StateHealthy}
	forceCooldown(coolingA, time.Now().Add(30*time.Second), "网关繁忙", true)
	forceCooldown(coolingB, time.Now().Add(45*time.Second), "网关限流", true)
	pool := poolOfEntries(coolingA, coolingB)

	_, err := pool.Do(context.Background(), httptest.NewRecorder(), chatRequestBody("Fake-Model"), nil)
	var noAcc *NoAccountError
	if !errors.As(err, &noAcc) {
		t.Fatalf("expected NoAccountError, got %T: %v", err, err)
	}
	if noAcc.Total != 2 || noAcc.RetryAfter <= 0 {
		t.Errorf("NoAccountError = %+v, want 2 accounts and a positive wait", noAcc)
	}

	handler := MakeChatHandler(resolverWithPool(pool, "key1", "dev key"), nil, nil)
	w := httptest.NewRecorder()
	handler(w, mkChatReq(`{"model":"Fake-Model","stream":false,"messages":[{"role":"user","content":"hi"}]}`))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body %s)", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("an admission-cooled pool must give the client a Retry-After")
	}
	if !strings.Contains(w.Body.String(), "rate_limit_error") {
		t.Errorf("body = %s, want a rate_limit_error type", w.Body.String())
	}
}

// No account in the pool can serve images: each answers with a capability miss,
// which is a routing fact rather than a provider fault, so the client gets a 400.
func TestChatHandlerMapsPoolWideCapabilityMissTo400(t *testing.T) {
	a := newFakeBridge(t, &fakeGateway{})
	b := newFakeBridge(t, &fakeGateway{})
	lr := logs.NewRecorder(nil, 90, 2000)
	handler := MakeChatHandler(resolverFor(a, b), nil, lr)

	w := httptest.NewRecorder()
	handler(w, mkChatReq(`{"model":"Fake-Model","messages":[{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Image input is not supported") {
		t.Errorf("body = %s, want the capability explanation", w.Body.String())
	}
	e := onlyLogEntry(t, lr)
	if e.StatusCode != 400 || len(e.Attempts) != 2 {
		t.Errorf("log entry = %d with %d attempts, want 400 after both accounts were tried", e.StatusCode, len(e.Attempts))
	}
}

// /v1/models must list whatever any account can serve, not only the first
// account's catalog: a model a heavier or hand-stopped account owns stays listed.
func TestPoolModelsUnionsEveryAccountCatalog(t *testing.T) {
	other := `{"chat":[{"key":"other_key","display_name":"Other-Model","enable":true,"is_vl":false,"is_reasoning":false,"max_output_tokens":2048}]}`
	a := newFakeBridge(t, &fakeGateway{})
	b := newFakeBridge(t, &fakeGateway{modelListJSON: other})

	p := newTestPool(
		testAccount{id: "a", bridge: a},
		testAccount{id: "b", bridge: b, off: true},
	)
	cat := p.Models(context.Background())
	if cat == nil {
		t.Fatal("expected a merged catalog")
	}
	for _, name := range []string{"Fake-Model", "Other-Model"} {
		if _, ok := cat.ModelMap[name]; !ok {
			t.Errorf("union is missing %q: %+v", name, cat.ModelMap)
		}
	}
}

// The request log must name the account that actually served the request, and
// carry the failover trail whenever a request cost more than one account.
func TestChatHandlerLogsServingAccountAndAttempts(t *testing.T) {
	bad := newFakeBridge(t, &fakeGateway{chatStatus: http.StatusUnauthorized})
	good := newFakeBridge(t, &fakeGateway{chatLines: okStream(t, "ok")})
	lr := logs.NewRecorder(nil, 90, 2000)

	pool := newTestPool(
		testAccount{id: "first", note: "A", bridge: bad},
		testAccount{id: "second", note: "B", bridge: good},
	)
	handler := MakeChatHandler(resolverWithPool(pool, "key1", "dev key"), nil, lr)
	handler(httptest.NewRecorder(), mkChatReq(`{"model":"Fake-Model","stream":true,"messages":[{"role":"user","content":"hi"}]}`))

	e := onlyLogEntry(t, lr)
	if e.TokenID != "second" || e.TokenNote != "B" {
		t.Errorf("serving account = %q/%q, want second/B", e.TokenID, e.TokenNote)
	}
	if len(e.Attempts) != 2 {
		t.Fatalf("attempts = %+v, want the failover trail", e.Attempts)
	}
	if e.Attempts[0].OK || e.Attempts[0].Error == "" {
		t.Errorf("failed first attempt = %+v", e.Attempts[0])
	}
	if e.StatusCode != 200 {
		t.Errorf("status = %d, want the failover's 200", e.StatusCode)
	}
}

// okStream builds the content + usage + [DONE] fixture a healthy account answers
// with, carrying the given text so a test can tell whose answer arrived.
func okStream(t *testing.T, text string) []string {
	t.Helper()
	return []string{
		sseFrame(t, map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]interface{}{"content": text}}}}),
		sseFrame(t, map[string]interface{}{"choices": []interface{}{}, "usage": map[string]interface{}{
			"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2, "credits": 0.1}}),
		"data: [DONE]",
	}
}

func chatRequestBody(model string) map[string]interface{} {
	return map[string]interface{}{
		"model":    model,
		"stream":   true,
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "hi"}},
	}
}

func onlyLogEntry(t *testing.T, lr *logs.Recorder) logs.LogEntry {
	t.Helper()
	if lr.Len() != 1 {
		t.Fatalf("log entries = %d, want 1", lr.Len())
	}
	return lr.Query(logs.Filter{PageSize: 1}).Logs[0]
}
