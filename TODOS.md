# TODOS

## Server contract (fivenines-server PR)

### 409 rule: same place after a restart or across nodes

**What:** Recognise "the same place" by more than (hostname, master pid, started_at) when a fingerprint changes.

**Why:** Since the 409 rule never adopts another identity (revision 2, "a copy is proposed, never added"), a URL change in the first push after a restart, or seen from a second node (web + dedicated cron node), gets a 409 and becomes a proposal: the administrator picks "Replaces an existing database" (a move is never guessed), and the data has a gap.

**Context:** docs/api-contract.md section 5, rule 1. Proof of continuity must not travel with a database copy: `events[].server_restart.previous` and `base_url_changed` do (they come from the database), so they cannot adopt. A candidate: the push's `stream_id` equals the last accepted one (it lives in the host-local `state.json`, not in the database, so it survives a process restart but not a restore elsewhere; not a VM snapshot either). The stub (`tests/stub_server.py`, collect) implements the current rule.

**Effort:** S
**Priority:** P2
**Depends on:** the server PR

### Two live places with the same fingerprint

**What:** Detect a PostgreSQL-level copy that pushes the same fingerprint (same name, uuid and URL) from another server.

**Why:** Both streams are accepted on one instance (dedup is per `stream_id`), so their counters add up. The contract says the server tells copies apart; for this case it does not.

Worse since revision 2 (review of PR #2, red team): such a copy's pushes interleave with production's, and when its admin logs in (Odoo rewrites `web.base.url`) while it was the last pusher, rule 1 ("same identity as the last accepted push: adopt") moves production's instance to the copy's fingerprint. Production then gets the 409 and lands as a pending copy: the takeover the founder's rule forbids.

**Context:** answer 409 (or flag) when the fingerprint is equal but identity and `stream_id` differ from the last accepted push within 15 minutes; and adopt a fingerprint change under rule 1 only when the identity (and `stream_id`) was stable over several pushes, not just the last one. Needs the lead's decision (rule 1 "stays" per the revision 2 brief).

**Effort:** S
**Priority:** P2
**Depends on:** the server PR

## Module: enrollment and state

### Keep previous_instance_id across a second Re-enroll

**What:** Re-enroll takes `previous_instance_id` only from `fivenines.instance_id`. Copies and 409s now keep the instance id until a new enrollment succeeds (#7), but a Re-enroll whose enrollment failed, followed by a second Re-enroll, has already forgotten it.

**Why:** The link to the old instance is lost (contract section 3 says it is kept until an enrollment succeeds).

**Context:** `models/fivenines_monitor.py` `_fn_run_locked` reenroll branch: `previous = params.get(P_INSTANCE) or (state.get('pending_enroll') or {}).get('previous_instance_id')`.

**Effort:** S
**Priority:** P2
**Depends on:** None

### Pending enrollment and backoff are per host

**What:** `pending_enroll` and `next_attempt_at` live in the host-local `state.json`, while the secret is per database.

**Why:** On several nodes, or a staging host refreshed nightly under the same name, a stale or missing state changes the enrollment reason. (Copies no longer depend on it: they are detected from the fingerprint stored in the database, #7.)

**Context:** store `pending_enroll` in `ir.config_parameter` (written rarely), or drop it when the database has neither secret nor fingerprint.

**Effort:** S
**Priority:** P3
**Depends on:** None

### Settings: say when the API URL field is ignored

**What:** With a key from odoo.conf/env, the Settings API URL is not used (enrollment goes to the server-wide URL; a secret goes to the URL that issued it, `fivenines.endpoint`). The field gives no hint.

**Why:** An administrator may change a field that has no effect.

**Context:** `views/res_config_settings_views.xml`, `models/res_config_settings.py`.

**Effort:** S
**Priority:** P4
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

**Why:** Error messages are now sent by default (#6), so this only matters with "Send error messages" off, where the module still promises to send templates only; these are common Odoo error shapes.

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

- A failing copy announcement retried every minute: its own failures now follow the bounded backoff (`state.json` `backoff_fingerprint`), test `test_failed_copy_announcement_backs_off`. (PR #2, lead review)

- Server-wide key moved the push URL of existing enrollments: a secret is now sent to the API URL that issued it (`fivenines.endpoint`). (fivenines_odoo #7)
- Neutralized copies: `neutralize.sql` is gone; a neutralized copy keeps its secret, stays off until "Turn it on" and announces itself with the copied secret. (fivenines_odoo #7)
