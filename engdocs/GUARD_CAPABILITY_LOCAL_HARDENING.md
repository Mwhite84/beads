# Guard capability presence hardening

`guardtx.Enabled` treats the two native guard tables as one capability. Zero tables
means unenrolled, both tables means enrolled, and a partial capability returns
`ErrUnsupported` before a native mutation transaction is admitted. Previously an
operations-only schema looked unenrolled because detection inspected only
`bd_guard_state`. The change does not repair partial schemas or rotate generation.

The isolated `internal/storage/guardtx` package tests cover rejection before work,
rollback, existing ordinary/no-op stamping and publication ownership. These tests
use a standard-library SQL driver seam; they do not claim a rebuilt CLI artifact
or full storage integration coverage. A rebuilt executable requires the full
repository dependencies and new artifact pins before rollout.

This is separate from enrollment fencing. An ordinary transaction that began
while the capability was absent cannot acquire a token retroactively. Production
enrollment still requires draining existing writers and preventing new ones during
the transition. The current experimental initializer provides a cooperative local
workspace gate, not a database-wide fence against direct SQL or remote clients.
Its disposable-data contract is unchanged; this patch introduces no production
enrollment command, operating approval, automatic migration or activation.
