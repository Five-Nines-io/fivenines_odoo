# TODOS

## Server contract (fivenines-server PR)

### 409 rule: same place after a restart or across nodes

**What:** Recognise "the same place" by more than (hostname, master pid, started_at) when a fingerprint changes.

**Why:** A URL change in the first push after a restart, or a URL change seen from a second node (web + dedicated cron node), gets a 409 and splits one database into two instances.

**Context:** docs/api-contract.md section 5, rule 1. Options: also accept a push whose `events[].server_restart.previous` equals the last accepted identity; adopt a `base_url`-only change (`fingerprint_change = base_url_changed`, same database name and uuid) whatever the identity. The stub (`tests/stub_server.py`, collect) implements the current rule.

**Effort:** S
**Priority:** P2
**Depends on:** the server PR

### Two live places with the same fingerprint

**What:** Detect a PostgreSQL-level copy that pushes the same fingerprint (same name, uuid and URL) from another server.

**Why:** Both streams are accepted on one instance (dedup is per `stream_id`), so their counters add up. The contract says the server tells copies apart; for this case it does not.

**Context:** answer 409 (or flag) when the fingerprint is equal but identity and `stream_id` differ from the last accepted push within 15 minutes; or correct the wording in section 5.

**Effort:** S
**Priority:** P2
**Depends on:** the server PR

## Module: enrollment and state

### Keep previous_instance_id across a second Re-enroll

**What:** Re-enroll takes `previous_instance_id` only from `fivenines.instance_id`; after a failed enrollment, a copy detection or a 409 (or on a neutralized copy, `fivenines.copied_from`) it is already gone.

**Why:** The link to the old instance is lost (contract section 3 says it is kept until an enrollment succeeds).

**Context:** `models/fivenines_monitor.py` `_fn_run_locked` reenroll branch: `previous = params.get(P_INSTANCE) or pending_enroll.previous_instance_id or params.get(P_COPIED_FROM)`.

**Effort:** S
**Priority:** P2
**Depends on:** None

### Pending enrollment and backoff are per host

**What:** `pending_enroll` and `next_attempt_at` live in the host-local `state.json`, while the secret is per database.

**Why:** On several nodes, or a staging host refreshed nightly under the same name, a stale or missing state changes the enrollment reason or delays a neutralized copy.

**Context:** store `pending_enroll` in `ir.config_parameter` (written rarely), or drop it when the database has neither secret nor fingerprint.

**Effort:** S
**Priority:** P3
**Depends on:** None

### Server-wide key moved the push URL of existing enrollments

**What:** With a key from odoo.conf/env, the Settings API URL is now ignored for pushes too, also for a secret issued by that URL.

**Why:** An install enrolled at a Settings URL with a server-wide key pushes to another endpoint after upgrade (401, then daily retry). The Settings field gives no hint that it is ignored.

**Context:** store the URL (or its level) with the secret at enrollment and pin only enrollment requests; show "ignored" in Settings.

**Effort:** S
**Priority:** P3
**Depends on:** None

### Counters dropped during a revoked hold

**What:** While revoked (24 h retry), dead workers' spool files are swept; a healed push then claims the whole window with `baseline_reset: false`.

**Why:** Silent under-counting after a server-side 401 mistake.

**Context:** do not sweep while a secret is kept, or set `baseline_reset` on the first push after the hold. Also: a new `stream` created on an upgraded `state.json` does not restart `seq` at 1 (`_fn_build_payload`).

**Effort:** S
**Priority:** P3
**Depends on:** None

## Module: log masking (privacy)

### Masking is a deny-list

**What:** Pre-formatted messages are masked by patterns; some shapes pass: an apostrophe in prose pairs with a value's opening quote ("Can't find partner 'John Smith'"), psycopg2 "Failing row contains (...)", unquoted names, a message with args whose template was partly pre-formatted (f-string + %s).

**Why:** The README promises no customer data; it documents the limit, but these are common Odoo error shapes.

**Context:** `lib/collector.py` `_MASKS`, `log_fingerprint`. Options: mask every template (also with args); mask parenthesized lists; send only logger/location/exception type when there is no lazy template. Long messages (> 2000 chars) keep only the text before the first quote (decision D8): safe, but less diagnostic, and a root cause can split into two fingerprints around 2000 chars.

**Effort:** M
**Priority:** P2
**Depends on:** None

## Module: settings UX

### Notification and status wording

**What:** The "revoked" toast still says "revoked" as a certainty; a timeout shows "Fivenines answered: retry"; the conflict toast says "another place"; `fivenines_last_error` still shows the server's message text.

**Why:** Admins get misleading or unclear messages; the last-error field echoes text from a possibly non-Fivenines URL.

**Context:** `models/res_config_settings.py` `_fivenines_notify`, `_compute_fivenines_status`.

**Effort:** S
**Priority:** P3
**Depends on:** None

## Tests

### Test gaps from the review

**What:** Assert the URL/query/quote/hex masks and the exact output of the no-quote cut branch; test `_register_hook`'s prefork-master detection; make the collector_errors assertion ignore `system.*` entries; a self-test for the `tools/run_tests.sh` gate; run `tools/e2e_local.py` in CI; record red-first proof for the pass-1 regression tests.

**Why:** These paths are covered only partly or by end-to-end runs.

**Context:** `tests/test_lib.py`, `tests/test_push.py`, `.github/workflows/ci.yml`.

**Effort:** M
**Priority:** P3
**Depends on:** None

## Performance

### Bounded but measurable per-record cost; slow endpoints

**What:** Masking a 2000-char pathological message still costs ~20 ms under the handler lock; requests' 10 s timeout is per read (no total deadline); `pg_database_size` runs every minute.

**Why:** Only matters under error floods, a trickling server, or very large databases on slow storage.

**Context:** `lib/collector.py` `mask_values`, `lib/client.py` `_post`, `_fn_collect_database`.

**Effort:** S
**Priority:** P4
**Depends on:** None

## Odoo.sh

### Verify on a real Odoo.sh project

**What:** Minimum cron interval and lateness under load, outbound HTTPS from the cron, readable cgroup files, the `ODOO_STAGE` variable name, whether staging databases are neutralized, and staging/dev cadence.

**Why:** Open questions of issue #1 that need an Odoo.sh project.

**Context:** the module's payload reports what is needed (`window.seconds`, `system.cgroup`, `instance.odoo_stage`, `last_error`).

**Effort:** M
**Priority:** P2
**Depends on:** an Odoo.sh project with admin rights

## Completed
