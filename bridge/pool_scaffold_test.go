package bridge

import "fmt"

// --- Test scaffolding for the token pool ---

// testAccount describes one pool entry a test is assembling.
type testAccount struct {
	id     string
	note   string
	weight int
	off    bool
	bridge *OpenAiBridge
}

// newTestPool builds a pool over bridges the test already owns (a stubbed
// transport, a fixed slot count). Production mints bridges from the token
// config; a test that pre-built one must not have to fake a PAT to get it into
// rotation. IDs default to the position when the test does not care about them.
func newTestPool(accounts ...testAccount) *Pool {
	p := &Pool{byID: make(map[string]*PoolEntry, len(accounts)), cur: make(map[string]int64, len(accounts))}
	for i, acc := range accounts {
		id := acc.id
		if id == "" {
			id = fmt.Sprintf("t%d", i)
		}
		w := acc.weight
		if w == 0 {
			w = 1
		}
		e := &PoolEntry{ID: id, note: acc.note, weight: w, off: acc.off, bridge: acc.bridge, state: StateHealthy}
		if acc.note == "" {
			e.note = id
		}
		p.entries = append(p.entries, e)
		p.byID[id] = e
	}
	// A fixed config with a generation the pool already matches: Sync() becomes a
	// no-op so the entries the test assembled survive every reconcile.
	p.gen = 1
	p.config = func() ([]TokenConfig, int64) { return nil, 1 }
	return p
}

// poolOfBridges is the common case: one account per bridge, equal weights.
func poolOfBridges(bridges ...*OpenAiBridge) *Pool {
	accounts := make([]testAccount, 0, len(bridges))
	for _, b := range bridges {
		accounts = append(accounts, testAccount{bridge: b})
	}
	return newTestPool(accounts...)
}

// resolverFor hands every request the pool over these bridges, as an anonymous
// key's access grant.
func resolverFor(bridges ...*OpenAiBridge) BridgeResolver {
	pool := poolOfBridges(bridges...)
	return func(string) *ResolvedAccess { return &ResolvedAccess{Pool: pool} }
}

// resolverForKey is resolverFor with the authenticated key's metadata attached —
// what the request log records alongside the serving account.
func resolverForKey(b *OpenAiBridge, keyID, keyNote string) BridgeResolver {
	pool := poolOfBridges(b)
	return func(string) *ResolvedAccess { return &ResolvedAccess{Pool: pool, KeyID: keyID, KeyNote: keyNote} }
}

// resolverWithPool hands every request an already-assembled pool, so a test that
// needs specific weights or health states can still drive the HTTP handler.
func resolverWithPool(p *Pool, keyID, keyNote string) BridgeResolver {
	return func(string) *ResolvedAccess { return &ResolvedAccess{Pool: p, KeyID: keyID, KeyNote: keyNote} }
}
