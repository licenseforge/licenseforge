# ADR-0036 Audit retention and SIEM export

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0027 Audit log](0027-audit-log.md) hash-chains every tenant's audit entries, allows retention only as a prefix cut, and expects a SIEM to hold an external anchor. [ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md) requires SIEM export over syslog (TLS) and OTel and an alert on audit failure (AU-5, AU-6, AU-9, AU-11). [ADR-0033 Platform audit chain](0033-platform-audit-chain.md) adds a chain that grows with every login, so `Verify`'s whole-chain walk doesn't scale. Decided under the maintainer's delegation.

## Decision
### Retention
- **Anchor**: `audit_anchors(tenant_id, seq, hash, cut_at)` holds the seq and hash of the last deleted entry; `Verify` starts after the anchor (or at seq 1 without one).
- **One prune transaction** takes the chain's lock, deletes the prefix, moves the anchor and appends a chained `audit.retention` entry naming the cut (`through_seq`, `through_hash`), so the cut itself is tamper-evident and exported.
- **Policy**: per-tenant `audit_retention_days`, unset = keep everything (ADR-0027's default). The database refuses deleting entries younger than **365 days** (restrictive DELETE policy), whatever the job asks.
- **Never prune unexported entries**: with a sink configured, the cut stops at the lowest export cursor for that chain.
- **Who**: a `licenseforge audit prune` CronJob with a **fifth database login** (`licenseforge_retention`: DELETE on `audit_events`, writes on `audit_anchors` only). Serving pods keep no DELETE right.

### Verification
- `Verify` reads in keyset pages (1,000 entries, one short transaction each), carrying the previous hash, resumable from the anchor or a previously verified head, so a periodic check costs O(new entries).

### Export
- **Push**: syslog (RFC 5424 over TLS, RFC 5425 framing, optional mTLS) and OTLP logs over HTTP. A pull API is for tenant self-export with the REST API, not the SIEM path.
- **Cursor per sink and chain** (`audit_export_cursors`): a replica claims a chain's cursor `FOR UPDATE SKIP LOCKED`, sends a batch, waits for the sink's acknowledgement, then advances. **At-least-once**; the SIEM deduplicates on entry ID. No leader election. Per-chain cursors, not a global sequence, because commit order isn't sequence order.
- **Payload**: every AU-3 field plus `seq`, `prev_hash` and `hash`, so the SIEM holds the external anchor (AU-9(3)).

### Audit failure
- Audit writes keep **failing closed**: an action whose entry can't be written is rolled back (AU-5).
- Metrics without tenant labels: write failures per chain, export failures and export lag per sink, verify failures; the chart ships an optional `PrometheusRule`.
- **A SIEM outage never blocks actions**: entries are delayed, not lost (lag plus the prune gate). An opt-in fail-closed-on-export setting can follow if a customer needs AU-5(2).

## Consequences
- A fifth login for self-hosters to create (one more Secret key); the database setup script and chart gain it.
- New tables (`audit_anchors`, `audit_export_cursors`) and migrations; PRs land in order: paging + write-failure metric, export core + syslog, OTLP, retention, periodic verify + alert rules, tenant self-export.
- OTLP uses the protobuf types only (`go.opentelemetry.io/proto/otlp`) or hand-written JSON, not the OTel SDK.

## Alternatives considered
- **A checkpoint entry without an anchor row**: `Verify` still needs to know where the surviving chain starts.
- **Rewriting the first entry after a cut**: breaks every exported hash.
- **Blocking actions while the SIEM is down**: turns one external system into an outage for every tenant.
- **Serving pods prune**: puts DELETE on audit entries into the internet-facing process.
