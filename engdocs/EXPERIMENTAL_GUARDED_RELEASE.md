# Local experimental guarded release

This local branch extends Beads 1.3.1 (`c1c4b642ac1c08d8c828007a1c2f96e47e43ef7c`) with an optional direct-server guarded-release role. It is a checkpoint for review and disposable testing. It does not activate a nightly audit or authorize a production writer cutover.

## Contract and commands

`bd guard initialize --experimental` explicitly creates the guard singleton and operation ledger in an exclusively opened workspace. Initialization is maintenance, not an automatic migration. `bd guard capture <issue>` returns the original database/branch/HEAD/root/generation/token identity and opaque server-selected state. `bd guard apply --request-json <path>` consumes a strict `beads.guard.v1` release request; `bd guard lookup --request-json <path>` resolves its stable operation ID and exact request digest. The Go API is in `guardops` and the implementation in `internal/storage/dolt/guarded_mutator.go`.

Apply compares the original capture before invoking the existing native release operation. It records the exact operation/digest/result alongside the release and conflict token. Exact replay checks the operation ledger before the now-stale original capture and returns the recorded result. Reusing the ID with different request content refuses. Publication errors return an unknown outcome; callers must use fresh Lookup before deciding what happened. An absent lookup does not silently authorize a blind retry or replacement capture.

Compatible ordinary transactions capture a composite working root, covering versioned state plus ignored leases, events and wisp dependencies. A real root change stamps a fresh shared token before publication; RowsAffected does not decide whether a same-value write changed state. Guard-enabled regular and ignored writes share native transaction ownership without enabling the optional events journal. Native leases and events retain their normal ignored-table semantics. Release, operation record and token share native history publication; ignored state is checked separately for SQL durability.

Guard commands suppress ordinary post-command flush/import/catalog/maintenance writes. Guard initialization uses the exclusive workspace gate. Embedded and proxied guard invocation refuses; the proxy registry returns `proxy.guard.unsupported` before creating a provider. Existing ordinary writer plumbing remains available, but that does not establish complete compatible-writer coverage.

## Evidence and operating limits

The task-local direct-server candidate compiles with cached Go 1.26.6, CGO disabled and `gms_pure_go`. The repository test wrapper runs actual native controls for release/replay/request mismatch, ordinary config/label/dependency/material invalidation, an ordered acknowledged ordinary-config race after tentative release, and successful real SQL Commit followed by injected acknowledgement loss and fresh-store recovery. Independent Krewe CLI transport and restart controls live outside this repository in the sibling proof directory; consult its current execution report for their result.

The root-owned harness uses only private loopback Dolt data and isolated HOME/Git/Dolt configuration. Existing frozen controls are preserved. Ordinary mock fixtures model the capability-absent probe while retaining their existing rollback, connection poisoning, journal and empty-commit assertions.

This experiment conservatively refuses mixed durable/ignored dependency graphs and ignored protected tables. Old binaries, raw SQL/import/restore/root maintenance and routine sync/merge can bypass the shared guard contract. Audit draining and generation invalidation are required operating boundaries and are not enforced here. Complete writer coverage, native no-op history, mixed-graph concurrent changes, initializer failure rollback, concurrent operation IDs and external hook delivery need further acceptance evidence. Hooks remain best-effort and are skipped on replay; exactly-once script delivery is not promised.

The Krewe admission layer remains separate: its tests use synthetic evidence, and no authenticated human-history/material/PR producer or automatic audit disposition pipeline is connected. Full audit archive, clearance and plan gates remain open. Full repository tests and the required lint contract must be reported independently from these focused controls; this branch is not claimed ready for upstream merge or deployment.
