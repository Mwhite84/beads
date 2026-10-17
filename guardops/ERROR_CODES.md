# Guard failure diagnostics

Primary and linked-explanation results may include `errorCode` on a failure.
The field is optional under the existing protocols. Old results without it stay
valid; successful durable results omit it. Codes do not authorize a retry or
assert that a write did not occur. Keep the original request for independent
lookup when the outcome is `unknown`.

The closed vocabulary is:

| Code | Meaning |
| --- | --- |
| `invalid-request` | Native request validation failed. |
| `history-publication-required` | The context defers native history publication. |
| `capability-unavailable` | The validated command cannot obtain its native role. |
| `context-unavailable` | The validated command cannot obtain its issue-operation context. |
| `unsupported-state` | A typed guard capability/state precondition failed. |
| `expectation-conflict` | The original expectation no longer matches. |
| `serialization-conflict` | A typed SQL lock timeout or deadlock occurred. |
| `request-mismatch` | The operation ID belongs to a different request digest. |
| `permission-denied` | A typed SQL access/privilege error occurred. |
| `schema-unavailable` | A typed SQL database/table/column availability error occurred. |
| `deadline-exceeded` | The operation context deadline expired. |
| `cancelled` | The operation context was cancelled. |
| `storage-failure` | The native error has no more specific supported classification. |
| `publication-unconfirmed` | Publication started or commit acknowledgement is indeterminate. |
| `lookup-unconfirmed` | Fresh durable lookup did not confirm an apparent application. |

Classification uses typed errors and sentinels, never free-form messages.
Publication uncertainty takes precedence over the underlying SQL classification.
No error message, SQL text, credential, path, or payload is included in a code.
Malformed framing and failures before request identity validation cannot acquire
a fabricated operation identity. A missing code cannot establish a historical
failure cause. Code changes require a coordinated downstream decoder update.
