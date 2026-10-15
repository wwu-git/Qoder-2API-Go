package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"qoder2api/auth"
	"qoder2api/bridge"
	"qoder2api/stats"
	"qoder2api/store"
)

func TestHealthHandler(t *testing.T) {
	s, err := store.New(t.TempDir() + "/data.json")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	pool := bridge.NewPool(tokenSource(s))
	h := healthHandler(pool)

	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}
	if resp["tokens"] != float64(0) || resp["available_tokens"] != float64(0) {
		t.Errorf("an empty pool = tokens %v / available %v, want 0/0", resp["tokens"], resp["available_tokens"])
	}
	if int(resp["chat_timeout_seconds"].(float64)) != store.DefaultChatTimeoutSeconds {
		t.Errorf("expected default chat timeout %d, got %v", store.DefaultChatTimeoutSeconds, resp["chat_timeout_seconds"])
	}

	if _, err := s.AddToken("pat-x", "first account", store.DefaultTokenWeight); err != nil {
		t.Fatalf("AddToken: %v", err)
	}
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/health", nil))
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("a pool with a usable account should be ok, got %v", resp["status"])
	}
	if resp["tokens"] != float64(1) || resp["available_tokens"] != float64(1) {
		t.Errorf("tokens %v / available %v, want 1/1", resp["tokens"], resp["available_tokens"])
	}

	// The probe reads cached pool state only: switching the one account off
	// makes the service not-ready, and it still answers 200.
	off := true
	if err := s.PatchToken(mustOnlyToken(t, s).ID, store.TokenPatch{Disabled: &off}); err != nil {
		t.Fatalf("PatchToken: %v", err)
	}
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/health", nil))
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "degraded" {
		t.Errorf("expected degraded when nothing may take traffic, got %v", resp["status"])
	}
	if resp["tokens"] != float64(1) || resp["available_tokens"] != float64(0) {
		t.Errorf("tokens %v / available %v, want 1/0", resp["tokens"], resp["available_tokens"])
	}
	if w.Code != 200 {
		t.Errorf("a degraded pool must still answer 200, got %d", w.Code)
	}
}

func mustOnlyToken(t *testing.T, s *store.Store) store.Token {
	t.Helper()
	list := s.ListTokens()
	if len(list) != 1 {
		t.Fatalf("expected exactly one token, got %d", len(list))
	}
	return list[0]
}

func TestHealthHandlerMethodNotAllowed(t *testing.T) {
	s, err := store.New(t.TempDir() + "/data.json")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	w := httptest.NewRecorder()
	healthHandler(bridge.NewPool(tokenSource(s)))(w, httptest.NewRequest("POST", "/health", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// Shutdown must not return before the HTTP drain completes. Cancelling the drain
// context early (as an earlier version did with a deferred cancel) turns
// graceful shutdown into an immediate abort of every in-flight streaming
// response on SIGTERM.
func TestShutdownWaitsForDrain(t *testing.T) {
	// A real server with a handler that outlives the background-loop join, so
	// the test exercises the actual srv.Shutdown contract rather than a stub.
	handlerEntered := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handlerEntered)
		<-release
		io.WriteString(w, "complete")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	type resp struct {
		body string
		err  error
	}
	clientDone := make(chan resp, 1)
	go func() {
		r, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			clientDone <- resp{err: err}
			return
		}
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		clientDone <- resp{body: string(b), err: err}
	}()
	<-handlerEntered

	accountStop := make(chan struct{})
	statsStop := make(chan struct{})
	accountDone := make(chan struct{})
	statsDone := make(chan struct{})
	// Both loops stop immediately, so the join adds no delay: any early return
	// would come from the cancelled drain context alone.
	close(accountDone)
	close(statsDone)

	shutdownErr := make(chan error, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		shutdown(shutdownErr, srv, &sync.Once{}, accountStop, statsStop, accountDone, statsDone)
	}()

	// The in-flight request must still be served: the drain has to wait for it.
	select {
	case <-returned:
		t.Fatal("shutdown returned before the in-flight request completed")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)

	select {
	case got := <-clientDone:
		if got.err != nil {
			t.Fatalf("in-flight request failed: %v", got.err)
		}
		if got.body != "complete" {
			t.Errorf("truncated response body %q; the drain was cancelled early", got.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight request never completed")
	}
	select {
	case err := <-shutdownErr:
		if err != nil {
			t.Errorf("shutdown error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown never reported")
	}
}

// aggregateAccounts is the single quota view the panel shows for the whole pool:
// allowances sum, the tag lists the distinct tiers, the countdown anchors on the
// earliest plausible boundary, and the org package (a shared pool every member
// sees) must not be double counted.
func TestAggregateAccountsSumsPool(t *testing.T) {
	parts := []*auth.AccountStatus{
		{
			Plan: "PLAN_TIER_PRO", UserTag: "Pro", OrgName: "acme",
			NextResetAtMs: 2_000,
			UserQuota:     &auth.Quota{Total: 100, Used: 40, Remaining: 60, Unit: "credits"},
			AddOnQuota:    &auth.Quota{Total: 10, Used: 4, Remaining: 6, Unit: "credits"},
			OrgResourcePackage: &auth.OrgResourcePackage{
				Used: 500, Cap: 1000, Remaining: 500, Available: true, Unit: "credits",
			},
		},
		{
			Plan: "PLAN_TIER_TEAM", UserTag: "Teams",
			NextResetAtMs: 1_000,
			UserQuota:     &auth.Quota{Total: 200, Used: 100, Remaining: 100, Unit: "credits"},
			// The same organization package, as every member sees it.
			OrgResourcePackage: &auth.OrgResourcePackage{
				Used: 500, Cap: 1000, Remaining: 500, Available: true, Unit: "credits",
			},
		},
		nil, // an account whose status could not be fetched must not read as zero
	}

	agg := aggregateAccounts(parts)
	if agg == nil {
		t.Fatal("expected an aggregate")
	}
	a := agg.Account
	if a.UserQuota == nil || a.UserQuota.Total != 300 || a.UserQuota.Used != 140 || a.UserQuota.Remaining != 160 {
		t.Errorf("user quota = %+v, want 300/140/160", a.UserQuota)
	}
	if a.UserQuota.Percentage != 140.0/300.0 {
		t.Errorf("aggregate percentage = %v, want %v", a.UserQuota.Percentage, 140.0/300.0)
	}
	if a.TotalUsagePercentage != 140.0/300.0 {
		t.Errorf("total usage percentage = %v", a.TotalUsagePercentage)
	}
	if a.AddOnQuota == nil || a.AddOnQuota.Total != 10 {
		t.Errorf("add-on quota = %+v", a.AddOnQuota)
	}
	if a.OrgResourcePackage == nil || a.OrgResourcePackage.Cap != 1000 {
		t.Errorf("org package = %+v, want the first one taken once", a.OrgResourcePackage)
	}
	if a.Tag != "Pro/Teams" {
		t.Errorf("tag = %q, want \"Pro/Teams\"", a.Tag)
	}
	if a.Plan != "PLAN_TIER_PRO" || a.OrgName != "acme" {
		t.Errorf("plan/org = %q/%q", a.Plan, a.OrgName)
	}
	if agg.NextResetMs != 1_000 {
		t.Errorf("next reset = %d, want the earliest boundary 1000", agg.NextResetMs)
	}
	if a.IsQuotaExceeded {
		t.Error("a pool with usable accounts must not report exhausted")
	}
}

// One exhausted account is a routing decision for the pool, not the pool's
// state: the aggregate only says "no credits" once every account agrees.
func TestAggregateAccountsExhaustedOnlyWhenAllAre(t *testing.T) {
	one := []*auth.AccountStatus{
		{IsQuotaExceeded: true, UserQuota: &auth.Quota{Total: 100, Used: 100}},
		{UserQuota: &auth.Quota{Total: 100, Used: 20}},
	}
	if aggregateAccounts(one).Account.IsQuotaExceeded {
		t.Error("a pool with one usable account is not exhausted")
	}
	both := []*auth.AccountStatus{
		{IsQuotaExceeded: true, UserQuota: &auth.Quota{Total: 100, Used: 100}},
		{IsQuotaExceeded: true, UserQuota: &auth.Quota{Total: 100, Used: 100}},
	}
	if agg := aggregateAccounts(both); !agg.Account.IsQuotaExceeded {
		t.Error("every account exhausted must read as exhausted")
	}
}

// The gateway's far-future "never expires" sentinel must not become the panel's
// countdown target, and a pool with no fetched status has no aggregate at all.
func TestAggregateAccountsResetSentinelAndEmpty(t *testing.T) {
	agg := aggregateAccounts([]*auth.AccountStatus{
		{NextResetAtMs: maxPlausibleResetMs * 2, UserQuota: &auth.Quota{Total: 1, Used: 0, Remaining: 1}},
	})
	if agg == nil {
		t.Fatal("expected an aggregate")
	}
	if agg.NextResetMs != 0 {
		t.Errorf("the never-expires sentinel leaked into the countdown: %d", agg.NextResetMs)
	}
	if agg.Account.Tag != "" {
		t.Errorf("tag = %q, want empty when no account carries one", agg.Account.Tag)
	}
	if aggregateAccounts(nil) != nil {
		t.Error("an empty part list must produce no aggregate, not a zeroed one")
	}
}

// The account loop owns the panel's single quota bar. With no accounts
// configured it must clear the aggregate it persisted before, otherwise a
// restart (or a token deletion) keeps showing an account that is gone.
func TestRefreshAccountsClearsRecorderForEmptyPool(t *testing.T) {
	s, err := store.New(t.TempDir() + "/data.json")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	rec := stats.NewRecorder(nil)
	rec.SetAccount(&stats.Account{Plan: "PLAN_TIER_PRO", Tag: "Pro"})
	if rec.Report().Account == nil {
		t.Fatal("test setup: expected an account before the refresh")
	}

	pool := bridge.NewPool(tokenSource(s))
	refreshAccounts(context.Background(), pool, s, rec)

	if got := rec.Report().Account; got != nil {
		t.Errorf("the stale aggregate survived an empty pool: %+v", got)
	}
}

// An unreachable gateway yields no snapshots. That is not the same as the
// accounts being out of credits, so the last known state stays on the panel.
func TestRefreshAccountsKeepsLastKnownWhenUpstreamIsSilent(t *testing.T) {
	agg := aggregateAccounts(nil)
	if agg != nil {
		t.Fatalf("expected no aggregate from an empty snapshot list, got %+v", agg)
	}
	// The nil-aggregate branch of refreshAccounts returns without touching the
	// recorder, so a previously set account must still be there.
	s, err := store.New(t.TempDir() + "/data.json")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	rec := stats.NewRecorder(nil)
	pool := bridge.NewPool(func() ([]bridge.TokenConfig, int64) {
		// One entry whose bridge was never minted: refreshAccounts skips it and
		// ends up with no snapshots, exactly like an unreachable gateway.
		return []bridge.TokenConfig{{ID: "t1", PAT: "", Note: "x", Weight: 1}}, 1
	})
	refreshAccounts(context.Background(), pool, s, rec)
	if got := rec.Report().Account; got != nil {
		t.Errorf("an unreachable upstream must not invent a pool state: %+v", got)
	}
}

// Shutdown must join the account refresher before triggering the stats loop's
// final flush: the account loop may still be mid-fetch, and a
// SetAccount/SetBillingCycle landing after that flush would be lost on exit.
func TestStopBackgroundLoopsOrdersAccountBeforeFlush(t *testing.T) {
	accountStop := make(chan struct{})
	statsStop := make(chan struct{})
	accountDone := make(chan struct{})
	statsDone := make(chan struct{})

	order := make(chan string, 2)
	// Models an in-flight account fetch: it notices its stop signal only after
	// this delay, and its last write lands just before accountDone closes.
	go func() {
		<-accountStop
		time.Sleep(50 * time.Millisecond)
		order <- "account-stopped"
		close(accountDone)
	}()
	// Models the stats loop, which performs the final flush on stop.
	go func() {
		<-statsStop
		order <- "final-flush"
		close(statsDone)
	}()

	stopBackgroundLoops(&sync.Once{}, accountStop, statsStop, accountDone, statsDone)

	if got := <-order; got != "account-stopped" {
		t.Fatalf("expected the account loop to finish first, got %q", got)
	}
	if got := <-order; got != "final-flush" {
		t.Errorf("expected the final flush after the account join, got %q", got)
	}
}

// A second stop request (a future "second signal forces exit" path, or a
// duplicate call) must block until the first stop finishes and then return
// without panicking on a double close of the stop channels.
func TestStopBackgroundLoopsIsIdempotent(t *testing.T) {
	accountStop := make(chan struct{})
	statsStop := make(chan struct{})
	accountDone := make(chan struct{})
	statsDone := make(chan struct{})

	order := make(chan string, 2)
	go func() {
		<-accountStop
		order <- "account-stopped"
		close(accountDone)
	}()
	go func() {
		<-statsStop
		order <- "final-flush"
		close(statsDone)
	}()

	once := &sync.Once{}
	stopBackgroundLoops(once, accountStop, statsStop, accountDone, statsDone)

	// A second call must neither panic nor run the body again: it returns as
	// soon as the Once has fired.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stopBackgroundLoops(once, accountStop, statsStop, accountDone, statsDone)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a repeated stopBackgroundLoops call did not return")
	}

	if got := <-order; got != "account-stopped" {
		t.Fatalf("expected the account loop to finish first, got %q", got)
	}
	if got := <-order; got != "final-flush" {
		t.Errorf("expected the final flush after the account join, got %q", got)
	}
	select {
	case extra := <-order:
		t.Errorf("the stop body ran more than once: %q", extra)
	default:
	}
}

// tokenSource must hand the pool the store's mutation generation, otherwise the
// pool never reconciles and a newly added token stays invisible.
func TestTokenSourceAdvancesGeneration(t *testing.T) {
	s, err := store.New(t.TempDir() + "/data.json")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	src := tokenSource(s)
	_, gen0 := src()
	if _, err := s.AddToken("pat-a", "a", 3); err != nil {
		t.Fatalf("AddToken: %v", err)
	}
	tokens, gen1 := src()
	if gen1 == gen0 {
		t.Fatal("adding a token did not advance the generation")
	}
	if len(tokens) != 1 || tokens[0].PAT != "pat-a" || tokens[0].Weight != 3 {
		t.Fatalf("token config = %+v", tokens)
	}

	pool := bridge.NewPool(src)
	if pool.Len() != 1 {
		t.Fatalf("pool.Len = %d, want 1", pool.Len())
	}
	if e := pool.Find(tokens[0].ID); e == nil || e.Bridge() == nil {
		t.Error("the pool did not mint a bridge for the configured token")
	}
}
