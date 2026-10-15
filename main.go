// qoder2api: OpenAI-compatible API bridge for QoderWork.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"qoder2api/admin"
	"qoder2api/auth"
	"qoder2api/bridge"
	"qoder2api/logs"
	"qoder2api/models"
	"qoder2api/stats"
	"qoder2api/store"
	"qoder2api/web"

	"sync"
	"time"
)

// Version is the build version, overridden at build time via
// -ldflags "-X main.Version=v1.2.3". It is only used for display (login page).
var Version = "dev"

// tokenSource adapts the store to the bridge pool's config contract. The pool
// reconciles on the generation counter, so the secret-bearing list is only
// walked when the config actually changed.
func tokenSource(st *store.Store) bridge.ConfigSource {
	return func() ([]bridge.TokenConfig, int64) {
		tokens := st.ListTokens()
		out := make([]bridge.TokenConfig, 0, len(tokens))
		for _, t := range tokens {
			out = append(out, bridge.TokenConfig{
				ID: t.ID, PAT: t.PAT, Note: t.Note, Weight: t.Weight, Disabled: t.Disabled,
			})
		}
		return out, st.TokensGen()
	}
}

// resolveAccess validates the client's API key and hands it the pool. A nil
// result means the key itself is unknown; an empty pool is a different answer
// and is reported by the pool as 503, never as a 401 against the client.
func resolveAccess(st *store.Store, pool *bridge.Pool) bridge.BridgeResolver {
	return func(apiKey string) *bridge.ResolvedAccess {
		key, ok := st.LookupKey(apiKey)
		if !ok {
			return nil
		}
		return &bridge.ResolvedAccess{Pool: pool, KeyID: key.ID, KeyNote: key.Note}
	}
}

// accountRefreshCadence keeps the authoritative allowance reasonably fresh
// without coupling the admin panel's 15-second poll to an upstream request.
const accountRefreshCadence = time.Minute

// accountWriteMu serializes the recorder writes of the account loop against a
// pool edit. The loop re-checks the pool generation after each fetch and drops a
// snapshot that no longer matches the config, so a removed account cannot be
// folded into the aggregate after the operator deleted it. The lock is never
// held across an upstream fetch.
var accountWriteMu sync.Mutex

// refreshAccounts walks every account in the pool: it bootstraps or renews that
// account's session, warms its model catalog, and pulls its authoritative quota
// snapshot (which is also what takes an exhausted account out of rotation).
//
// The per-account snapshot stays on the bridge; the recorder only ever sees the
// aggregate, because the panel shows one quota bar, not N of them.
func refreshAccounts(ctx context.Context, pool *bridge.Pool, st *store.Store, rec *stats.Recorder) {
	gen := st.TokensGen()
	entries := pool.Entries()

	if len(entries) == 0 {
		accountWriteMu.Lock()
		defer accountWriteMu.Unlock()
		if st.TokensGen() == gen {
			rec.ClearAccount()
		}
		return
	}

	parts := make([]*auth.AccountStatus, 0, len(entries))
	for _, e := range entries {
		b := e.Bridge()
		if b == nil {
			continue
		}
		if status := b.EnsureAccountStatus(ctx); status != nil {
			parts = append(parts, status)
		}
		// Warmed here so the request path never pays for a catalog fetch.
		b.GetCatalog(ctx)
	}

	aggregate := aggregateAccounts(parts)
	if aggregate == nil {
		return // upstream unreachable: keep the last known state
	}
	accountWriteMu.Lock()
	defer accountWriteMu.Unlock()
	if st.TokensGen() != gen {
		return // the pool was edited while these fetches were in flight
	}
	rec.SetBillingCycle(aggregate.NextResetMs)
	rec.SetAccount(aggregate.Account)
}

// poolAggregate is the single quota view the statistics panel shows for the
// whole pool, plus the billing-cycle anchor it counts down to: when several
// accounts each have their own boundary, the earliest plausible one.
type poolAggregate struct {
	NextResetMs int64
	Account     *stats.Account
}

// aggregateAccounts folds the per-account gateway snapshots into the single
// quota view the statistics panel shows: allowances sum, the plan tag lists the
// distinct tiers, and an account counts as exhausted only when every one of them
// is. Missing snapshots are skipped rather than treated as zero.
func aggregateAccounts(parts []*auth.AccountStatus) *poolAggregate {
	if len(parts) == 0 {
		return nil
	}
	agg := &poolAggregate{Account: &stats.Account{}}
	var tags []string
	allExhausted := true
	for _, st := range parts {
		if st == nil {
			continue
		}
		if st.Plan != "" && agg.Account.Plan == "" {
			agg.Account.Plan = st.Plan
		}
		if st.OrgName != "" && agg.Account.OrgName == "" {
			agg.Account.OrgName = st.OrgName
		}
		if st.UserTag != "" && !containsStr(tags, st.UserTag) {
			tags = append(tags, st.UserTag)
		}
		if !st.IsQuotaExceeded {
			allExhausted = false
		}
		if r := minPlausibleReset(st.NextResetAtMs); r != 0 && (agg.NextResetMs == 0 || r < agg.NextResetMs) {
			agg.NextResetMs = r
		}
		sumQuota(&agg.Account.UserQuota, st.UserQuota)
		sumQuota(&agg.Account.AddOnQuota, st.AddOnQuota)
		sumOrgPackage(&agg.Account.OrgResourcePackage, st.OrgResourcePackage)
	}
	agg.Account.IsQuotaExceeded = allExhausted
	switch {
	case len(tags) == 0:
	case len(tags) == 1:
		agg.Account.Tag = tags[0]
	default:
		agg.Account.Tag = strings.Join(tags, "/")
	}
	if q := agg.Account.UserQuota; q != nil && q.Total > 0 {
		q.Percentage = q.Used / q.Total
		agg.Account.TotalUsagePercentage = q.Percentage
	}
	return agg
}

// sumQuota adds one account's allowance bucket into the aggregate. Unit and
// detail URL come from the first account that carries them: they are the same
// product field for every account.
func sumQuota(dst **stats.Quota, src *auth.Quota) {
	if src == nil {
		return
	}
	if *dst == nil {
		*dst = &stats.Quota{Unit: src.Unit, DetailURL: src.DetailURL}
	}
	(*dst).Total += src.Total
	(*dst).Used += src.Used
	(*dst).Remaining += src.Remaining
}

// sumOrgPackage adds one account's view of the shared organization pool. The
// gateway reports the same package to every member of an organization, so a
// package seen on more than one account must not be double counted: the first
// non-empty one wins.
func sumOrgPackage(dst **stats.OrgResourcePackage, src *auth.OrgResourcePackage) {
	if src == nil || *dst != nil {
		return
	}
	*dst = &stats.OrgResourcePackage{
		Used: src.Used, Cap: src.Cap, Remaining: src.Remaining,
		Percentage: src.Percentage, Available: src.Available, Unit: src.Unit,
	}
}

// minPlausibleReset returns ms when it is a real subscription boundary; the
// gateway's far-future "never expires" sentinel must not become the panel's
// countdown target.
func minPlausibleReset(ms int64) int64 {
	if ms > 0 && ms < maxPlausibleResetMs {
		return ms
	}
	return 0
}

// maxPlausibleResetMs is 2100-01-01T00:00:00Z, matching the bridge-side bound.
const maxPlausibleResetMs = int64(4102444800000)

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// healthHandler serves an unauthenticated liveness/readiness probe. It is
// deliberately cheap (no upstream calls, no session bootstrap): the body
// carries readiness details (how many tokens are configured and how many may
// take traffic, plus the effective stream timeouts) while the status stays 200
// as long as the process is serving.
//
// The pool counts come from cached state, not a probe: an unhealthy token makes
// itself known here without this endpoint ever reaching the gateway.
func healthHandler(pool *bridge.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timeouts := auth.CurrentStreamTimeouts()
		tokens, available := pool.Len(), pool.Available()
		status := "ok"
		if tokens > 0 && available == 0 {
			status = "degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               status,
			"tokens":               tokens,
			"available_tokens":     available,
			"chat_timeout_seconds": int(timeouts.Header.Seconds()),
			"idle_timeout_seconds": int(timeouts.Idle.Seconds()),
		})
	}
}

func main() {
	// Initialize store
	dataPath := os.Getenv("QODER_DATA_PATH")
	if dataPath == "" {
		dataPath = "data.json"
	}
	st, err := store.New(dataPath)
	if err != nil {
		log.Fatalf("[store] failed to init: %v", err)
	}

	// Host/port: env vars override config file; config file overrides defaults
	host := os.Getenv("QODER_HOST")
	if host == "" {
		host = st.GetHost()
	}
	port := st.GetPort()
	if envPort := os.Getenv("QODER_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		} else {
			log.Printf("[bridge] WARN invalid QODER_PORT=%q; using %d", envPort, port)
		}
	}

	// Chat stream timeouts: env vars override the persisted config, the
	// config file overrides the built-in defaults (same precedence as
	// host/port). Applied to new requests immediately.
	chatTimeout := st.GetChatTimeoutSeconds()
	if v := os.Getenv("QODER_CHAT_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= store.MaxChatTimeoutSeconds {
			chatTimeout = n
		} else {
			log.Printf("[bridge] WARN invalid QODER_CHAT_TIMEOUT_SECONDS=%q; using %d", v, chatTimeout)
		}
	}
	idleTimeout := st.GetIdleTimeoutSeconds()
	if v := os.Getenv("QODER_IDLE_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= store.MaxIdleTimeoutSeconds {
			idleTimeout = n
		} else {
			log.Printf("[bridge] WARN invalid QODER_IDLE_TIMEOUT_SECONDS=%q; using %d", v, idleTimeout)
		}
	}
	auth.SetStreamTimeouts(time.Duration(chatTimeout)*time.Second, time.Duration(idleTimeout)*time.Second)

	// Request-log limits: env vars override the persisted config, which
	// overrides the built-in defaults (same precedence as the timeouts above).
	logRetention := st.GetLogRetentionDays()
	if v := os.Getenv("QODER_LOG_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= store.MaxLogRetentionDays {
			logRetention = n
		} else {
			log.Printf("[logs] WARN invalid QODER_LOG_RETENTION_DAYS=%q; using %d", v, logRetention)
		}
	}
	logMaxEntries := st.GetLogMaxEntries()
	if v := os.Getenv("QODER_LOG_MAX_ENTRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= store.MinLogMaxEntries && n <= store.MaxLogEntriesHardCap {
			logMaxEntries = n
		} else {
			log.Printf("[logs] WARN invalid QODER_LOG_MAX_ENTRIES=%q; using %d", v, logMaxEntries)
		}
	}

	// One bridge per configured PAT, selected by weight and failed over while
	// the response is still uncommitted.
	pool := bridge.NewPool(tokenSource(st))

	// Request statistics recorder with periodic persistence (30s cadence).
	// The loop also drains a stop channel so graceful shutdown can trigger a
	// final flush, avoiding loss of the last <=30s of stats.
	rec := stats.NewRecorder(st)
	// Request-log recorder: same persistence model as stats (in-memory on the
	// request path, flushed out of band). Entries are metadata only.
	logRec := logs.NewRecorder(st, logRetention, logMaxEntries)
	// The aggregate is persisted, so a restart after the pool was edited would
	// otherwise keep showing an account that is no longer configured. Drop it
	// once here; the account loop repopulates the panel from the first
	// successful refresh.
	rec.ClearAccount()
	statsStop := make(chan struct{})
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		flushAll := func(final bool) {
			if err := rec.Flush(); err != nil {
				log.Printf("[stats] WARN %sflush failed: %v", finalStr(final), err)
			}
			if err := logRec.Flush(); err != nil {
				log.Printf("[logs] WARN %sflush failed: %v", finalStr(final), err)
			}
		}
		for {
			select {
			case <-ticker.C:
				flushAll(false)
			case <-statsStop:
				flushAll(true)
				return
			}
		}
	}()

	// Model list for the admin panel: the union of the pool's catalogs.
	modelFetcher := func(ctx context.Context) []string {
		if pool.Len() == 0 {
			return models.DefaultCatalog().Keys()
		}
		return pool.Models(ctx).Keys()
	}

	// Subscription account loop: for every account in the pool it bootstraps or
	// renews the session, warms the model catalog, and refreshes the identity
	// metadata from /user/status plus the authoritative allowance from OpenAPI
	// /api/v2/quota/usage — all out of band. The admin panel's 15-second poll
	// remains memory-only.
	//
	// The loop has its own stop/done pair so shutdown can join it before the
	// final stats flush: its last SetAccount/SetBillingCycle would otherwise
	// land after that flush and be lost on exit.
	accountStop := make(chan struct{})
	accountDone := make(chan struct{})
	go func() {
		defer close(accountDone)
		// Fetch once immediately so the panel is populated from the start
		// rather than after the first tick, and so a freshly added token does
		// not make the client pay for a cold session on its first request.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		refreshAccounts(ctx, pool, st, rec)
		cancel()

		ticker := time.NewTicker(accountRefreshCadence)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				refreshAccounts(ctx, pool, st, rec)
				cancel()
			case <-accountStop:
				return
			}
		}
	}()

	// Initialize admin
	adminInst := admin.New(st, modelFetcher, rec, logRec, pool)

	// WebUI: pre-render all pages at startup (multi-page Alpine.js frontend,
	// no build step, no external dependencies).
	webHandler, err := web.New(Version)
	if err != nil {
		log.Fatalf("[web] failed to init: %v", err)
	}

	resolver := resolveAccess(st, pool)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", bridge.MakeChatHandler(resolver, rec, logRec))
	mux.HandleFunc("/v1/models", bridge.MakeModelsHandler(resolver))
	mux.HandleFunc("/health", healthHandler(pool))

	// Root redirect to admin UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	// Register admin API routes (/admin/api/*) and WebUI routes
	// (/admin, /admin/<page>, /admin/assets/*)
	adminInst.RegisterRoutes(mux)
	webHandler.Mount(mux)

	addr := host + ":" + strconv.Itoa(port)
	log.Printf("[bridge] listening http://%s/v1/chat/completions", addr)
	log.Printf("[admin]  http://%s/admin", addr)

	// Timeouts: ReadHeaderTimeout/IdleTimeout harden against slowloris-style
	// resource exhaustion. WriteTimeout is intentionally unset so that
	// long-lived SSE streaming responses are not prematurely cancelled.
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM: stop the account refresher and join
	// it, trigger the final stats flush, and drain in-flight requests with a
	// bounded deadline.
	//
	// stopOnce is shared by every caller of shutdown/stopBackgroundLoops so a
	// second signal (or a future forced-exit path) cannot panic on a double
	// close of the stop channels.
	stopOnce := &sync.Once{}
	shutdownErr := make(chan error, 1)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		// Unregister before tearing down: restoring the default disposition
		// means a second signal terminates the process immediately instead of
		// being queued into a handler that has already run. The stop channels
		// themselves are guarded by sync.Once, so a duplicate teardown is safe.
		signal.Stop(sigCh)
		log.Printf("[server] received %s, shutting down...", sig)
		shutdown(shutdownErr, srv, stopOnce, accountStop, statsStop, accountDone, statsDone)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[server] failed to listen on %s: %v\n[server] If port %d is in use, change it in the admin UI or data.json", addr, err, port)
	}
	if err := <-shutdownErr; err != nil {
		log.Printf("[server] shutdown error: %v", err)
	}
	// Wait for the stats goroutine to finish its final flush before exiting.
	<-statsDone
	log.Printf("[server] stopped")
}

// finalStr labels a flush log line ("final " on shutdown) so periodic and
// shutdown flushes stay distinguishable.
func finalStr(final bool) string {
	if final {
		return "final "
	}
	return ""
}

// shutdown stops the background loops and drains in-flight requests. The drain
// runs concurrently with the join so a slow account refresh cannot delay it, but
// it is still awaited before this returns: cancelling the drain's context early
// would abort every in-flight streaming response on SIGTERM, which is what a
// previous version of this function did. The stop channels are closed through
// stopOnce, so a repeated shutdown call cannot panic.
func shutdown(shutdownErr chan<- error, srv *http.Server, stopOnce *sync.Once, accountStop, statsStop chan<- struct{}, accountDone, statsDone <-chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	drain := make(chan error, 1)
	go func() { drain <- srv.Shutdown(ctx) }()
	stopBackgroundLoops(stopOnce, accountStop, statsStop, accountDone, statsDone)
	shutdownErr <- <-drain
	cancel()
}

// stopBackgroundLoops joins the account refresher before triggering the stats
// loop's final flush: the account loop may be mid-fetch for up to 30s, and a
// SetAccount/SetBillingCycle landing after that flush would be lost on exit.
//
// once guards every stop-channel close, so a second caller (a future
// "second signal forces exit" path, or a duplicate call) blocks until the
// first stop completes and then returns instead of panicking on a double
// close. Callers supply the Once so independent instances stay independent.
func stopBackgroundLoops(once *sync.Once, accountStop, statsStop chan<- struct{}, accountDone, statsDone <-chan struct{}) {
	once.Do(func() {
		close(accountStop)
		<-accountDone
		close(statsStop)
		<-statsDone
	})
}
