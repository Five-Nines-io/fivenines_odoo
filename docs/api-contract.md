# Fivenines Odoo API contract (v1)

This is the contract between the `fivenines_monitoring` Odoo module and the Fivenines server.
The module side is implemented in this repository. The server side is not written yet: this
document is the spec for that later fivenines-server PR. A stub that implements it lives in
`fivenines_monitoring/tests/stub_server.py`. The module's tests and the end-to-end check use it.

Machine-readable schemas (JSON Schema 2020-12, the subset the stub validates):

- `fivenines_monitoring/tests/schemas/enroll_request.schema.json`
- `fivenines_monitoring/tests/schemas/push_payload.schema.json`

When this document and a schema disagree, the schema wins. Fix both in the same PR.

## 1. Principles

- **Push only.** Each Odoo database ("instance") calls Fivenines from a scheduled action
  (`ir.cron`) once a minute. Fivenines never connects to Odoo.
- **One enrollment key per organization, one secret per instance.** The key is pasted in every
  instance you want to monitor. The instance sends it once, to `POST /odoo/v1/enroll`, and gets
  back a secret (`token`) that belongs to that instance only. From then on only the secret is
  used. **The key is used once and never kept in the database:** a key pasted in Settings is
  deleted as soon as the enrollment succeeds (a key in the Odoo config file or the environment
  stays where the operator put it). A key pasted later is kept only while the database needs
  one (revoked, ignored, a copy that needs a key) and until it is used; otherwise the next run
  deletes it. This mirrors how the agent works today (`ApiController#authenticate_host!` and
  `#enroll_host_via_token`): an `EnrollmentToken` (`SecureRandom.hex(32)`, revocable,
  `hosts_registered_count`, `last_used_at`) is swapped for a per-host `client_token`. The
  difference is that the Odoo module has a dedicated enrollment call instead of the agent's
  "first `/collect` carries the enrollment token and the answer carries `token`" swap. That keeps
  the enrollment key out of every metrics request.
- **Revocation.** Revoking an instance secret cuts that instance only. The module stops pushing,
  never re-enrolls on its own, and tries the same secret again once a day (so a server-side
  mistake heals by itself). Revoking the enrollment key blocks new enrollments only.
- **Copies announce themselves with the secret they carry.** The module sends a location
  fingerprint. When the database name, `database.uuid`, Odoo.sh stage or the neutralized flag
  changes, the database is a copy: it calls `/enroll` with the COPIED secret (no key needed) and
  the server mints a new secret for a new database, proposed for approval. A `web.base.url`
  change alone is adopted and flagged; the server tells a second live place apart (section 5).
- **Approval.** The server may hold a new database as **pending** ("waiting for approval"):
  the module keeps its credentials, sends nothing that would accumulate, and only checks again
  every `retry_after` seconds (default 900). Once accepted it pushes normally. **Ignored** is
  final for that database: the module stops, like after a revocation, with its own status.
- **Neutralization is respected.** A neutralized copy (Odoo.sh staging, `odoo-bin neutralize`)
  keeps its secret, but Odoo deactivated its push cron and the module never re-activates it by
  itself. One click on the copy's settings screen ("Turn it on") does; the copy then announces
  itself as above and lands as pending.
- **Unknown is `null`, never `0`.** A `0` in a payload is a measurement. Anything the module could
  not measure is `null` (or the whole block is `null`), and the reason may appear in
  `collector_errors`.

## 2. Transport

| | |
|---|---|
| Base URL | `https://api.fivenines.io` (overridable in the module, see the README) |
| Paths | `POST /odoo/v1/enroll`, `POST /odoo/v1/collect` |
| TLS | HTTPS only. The module refuses a plain `http://` URL except to a loopback IP literal or `localhost` (the stub; a DNS name such as `127.example.com` is not loopback) or when `fivenines_allow_insecure_http = True` is set in the Odoo config file. |
| URL source | When the enrollment key comes from the Odoo config file or the environment (server-wide), the API URL comes from the same level or the default, never from one database's Settings: a database administrator cannot redirect the organization key. |
| Timeout | The module waits 10 s for the connection and 10 s per read, then gives up until the next minute. |
| Redirects | Not followed. Answer at the URL. |
| Secret endpoint | An instance secret is only ever sent to the API URL that issued it (recorded at enrollment), whatever the Settings or config say later. |

### Request headers

| Header | Value |
|---|---|
| `Authorization` | On `/enroll`: `Bearer <enrollment key>`, or `Bearer <instance token>` when a copy announces itself with the secret it carries (the body's `credential` says which). On `/collect`: `Bearer <instance token>`. The ONLY place a credential appears: never in the URL or the body. The server reads it like `ApiController#client_token`: last space-separated word. |
| `Content-Type` | `application/json` |
| `Content-Encoding` | `gzip`. The module always compresses. The server must inflate (the agent API already does this in its middleware) and apply its body cap AFTER inflation. 2 MB is plenty: a real push is 3-30 KB of JSON before compression. |
| `Accept` | `application/json` |
| `User-Agent` | `fivenines-odoo/<module version> (Odoo <release.version>; Python <x.y.z>)`, e.g. `fivenines-odoo/19.0.1.0.0 (Odoo 19.0; Python 3.12.3)` |

### Response format

JSON object. Success: `{"status": "ok", ...}`. Error: `{"status": "error", "message": "..."}`, the
envelope `/collect` already uses for agents. The module logs `message` (truncated to 300 chars)
and shows it on its settings screen, so it must never contain a secret.

## 3. Enrollment: `POST /odoo/v1/enroll`

Sent:

- with the **enrollment key**: when the instance has no secret (first run after a key is
  configured), when an administrator clicks "Re-enroll" (which needs a key: without one the
  module forgets nothing), or when a copy's secret is refused (401) and a key is available;
- with the **instance secret** the database carries: when the fingerprint shows a copy
  (section 5), or after a 409 on `/collect`.

### Request body

```json
{
  "schema_version": 1,
  "credential": "enrollment_key",
  "reason": "first_enrollment",
  "previous_instance_id": null,
  "changed": [],
  "key_source": "settings",
  "instance": {
    "fingerprint": "7eaf547f64ce6a8de124c6ef4fbe1814536c18f13b0b3b205a40fff2ba2f3722",
    "fingerprint_components": {
      "database": "odoo",
      "database_uuid": "69bc4150-e9e8-11f1-9a52-06616917c26d",
      "base_url": "https://odoo.example.com",
      "odoo_stage": null,
      "neutralized": false
    },
    "database": "odoo",
    "database_uuid": "69bc4150-e9e8-11f1-9a52-06616917c26d",
    "base_url": "https://odoo.example.com",
    "odoo_stage": null,
    "urls": ["https://odoo.example.com", "https://shop.example.com"],
    "odoo_version": "19.0",
    "odoo_serie": "19.0",
    "odoo_version_info": [19, 0, 0, "final", 0, ""],
    "edition": "community",
    "module_version": "19.0.1.0.0",
    "python_version": "3.12.3",
    "hostname": "odoo-vm",
    "workers": 0,
    "max_cron_threads": 2
  }
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Always `1` for this contract. |
| `credential` | `enrollment_key` or `instance_secret`: what the `Authorization` header carries. |
| `reason` | `first_enrollment`, `fingerprint_changed` (a copy, section 5; also a copy enrolling with a key after its secret was refused), `conflict` (after a 409), `manual` ("Re-enroll" button). The reason and `previous_instance_id` are kept until an enrollment succeeds, so a retry after a failure carries them too. |
| `previous_instance_id` | The instance this database reported as before. `null` on a first enrollment. Lets the server show "copied from X" or offer to merge a move. |
| `changed` | The fingerprint components that differ from the stored ones (e.g. `["database_uuid"]`, `["neutralized"]`). Empty when not a copy, and after a 409 (the module saw no change). |
| `key_source` | Where the module found the key: `settings` (this database), `odoo.conf`, `environment`. `null` when `credential` is `instance_secret`. |
| `instance.fingerprint` | sha256 hex of the canonical JSON (sorted keys, `json.dumps(..., sort_keys=True)`) of `fingerprint_components`. |
| `instance.fingerprint_components.database` | PostgreSQL database name. |
| `instance.fingerprint_components.database_uuid` | `ir.config_parameter` `database.uuid`. |
| `instance.fingerprint_components.base_url` | `web.base.url`, normalized: lowercase scheme and host, default port dropped, trailing `/` dropped. |
| `instance.fingerprint_components.odoo_stage` | The `ODOO_STAGE` environment variable (`production`, `staging`, `dev` on Odoo.sh). `null` when self-hosted. |
| `instance.fingerprint_components.neutralized` | `database.is_neutralized` (set by Odoo's neutralization). A fingerprint stored before this component existed compares it as `false`. |
| `instance.urls` | Every URL the database knows, for matching existing uptime monitors: `web.base.url` first, then each `website.domain` (`https://` added when it has no scheme), normalized like `base_url`, without duplicates, at most 50. NOT part of the fingerprint: adding a website is not a copy. |
| `instance.odoo_version` / `odoo_serie` / `odoo_version_info` | `odoo.release.version`, `.serie`, `.version_info`. Enterprise builds look like `17.0+e`. |
| `instance.edition` | `enterprise` when `web_enterprise` is installed, else `community`. |
| `instance.module_version` | Manifest version of the module, e.g. `19.0.1.0.0`. |
| `instance.workers`, `max_cron_threads` | From the Odoo config. `workers = 0` means threaded mode. |

The `base_url` is the public URL: the server may offer to create an uptime monitor on it at
enrollment (the issue's install flow, step 4), or attach the existing monitors whose URL is in
`urls`.

### Responses

| Status | Body | Module behaviour |
|---|---|---|
| `201` (`200` when a secret's own, unchanged database announces itself again) | `{"status": "ok", "state": "monitored", "instance_id": "<string>", "token": "<secret>", "name": "<display name>"}` | Stores `token` and `instance_id` in `ir.config_parameter` (admins only), committed on their own cursor so a rolled-back transaction cannot cause a double enrollment, deletes a key pasted in Settings, then pushes in the same run. A 2xx without `token` or `instance_id` is treated as a retryable failure. |
| `202` | `{"status": "pending", "state": "pending", "instance_id": "<string>", "token": "<secret>", "name": "<display name>", "retry_after": 900}`: the database is proposed and waits for approval. | Stores the credentials like a 201 (the key is used: it is deleted), records the `pending` status with `name`, pushes nothing and checks again after `retry_after` seconds (see "Pending" below). |
| `410` | `{"status": "error", "code": "ignored", "name": "<display name>", "message": "..."}`: an administrator chose Ignore for this database (e.g. the same copy announcing itself again). | Records the `ignored` status (final, see below). |
| `401` | invalid or revoked credential | With the enrollment key: remembers the refused key (as a hash) and makes no more requests until the key changes or an admin clicks a button. With a copy's secret (the original was revoked): enrolls at once with the enrollment key if one is configured, else records `copy_needs_key` and waits for a key. |
| `402` | organization subscription inactive (same meaning as `/collect` today) | Retries in 1 hour. |
| `403` | instance limit reached (`PlanFeatures#instances_limit_reached?`) | Retries in 1 hour. |
| `422` / `400` / `413` | payload refused (contract drift) | Bounded backoff (section 7), warning logged at most every 15 min. |
| `429` | rate limited | Waits `Retry-After` seconds (capped at 1 hour), else 60 s. |
| `404`, `5xx`, timeout, connection error | not deployed yet / transient | Bounded backoff (section 7). |

#### Pending and ignored

- **Pending** (`202`, `state: "pending"`, on `/enroll` or `/collect`): the module keeps its
  secret and instance id, and does not accumulate anything for later: on a `202` to a push it
  drops the counters of that window (fresh baseline, spool files of dead processes deleted)
  because the server stored nothing. It checks again (one push) every `retry_after` seconds:
  the body's `retry_after`, else the `Retry-After` header, else 900, bounded to 300..21600. The
  first push after the database is accepted carries `window.baseline_reset = true` and only
  counts from the previous check. "Send now" checks at once.
- **Ignored** (`410` with `code: "ignored"`, on `/enroll` or `/collect`): final. The module
  keeps its secret but makes no automatic request at all any more. "Send now" asks once (a
  database un-ignored in Fivenines answers 200 and resumes); "Re-enroll" with a key proposes
  the database anew. The status is recorded with the fingerprint it applies to: an ignored copy
  stays silent, while a new copy of an ignored database still announces itself (its fingerprint
  changed). A `410` WITHOUT `code: "ignored"` (a retired path, a CDN) is a retryable failure,
  never the final state; likewise a `202` without `state: "pending"` is not an acknowledgement.
- **A copy whose copied secret is refused** (`401`) enrolls with the enrollment key at once,
  sent to the URL of the key's own level (section 2), never to the endpoint that issued the
  refused secret. Without a key it records `copy_needs_key` and makes no request until a key is
  configured or "Send now" is clicked.
- Pending and ignored show on the settings screen with the `name` the server returned.
- The holds above (ignored, `copy_needs_key`) are recorded with the copy they apply to (its
  database name, uuid, stage and neutralized flag, not `base_url`): an admin login that rewrites
  `web.base.url` on an ignored copy keeps it silent.

Server notes:

- Look the key up like `EnrollmentToken.active.lock.find_by(token:)`, bump
  `hosts_registered_count` and `last_used_at`, and refuse with 401 when it is unknown or revoked.
  The same organization key can serve agents and Odoo instances: the issue asks for "one
  enrollment key per Fivenines organization".
- `token`: `SecureRandom.hex(32)`, unique, revocable on its own, like `Host#client_token`.
- Store the fingerprint (hash + components) on the instance (needed for the 409 rule).
- An enrollment with `credential: "instance_secret"`: authenticate the secret like `/collect`
  (401 when unknown or revoked). If the fingerprint equals the instance's stored one and the
  reason is not `conflict`, answer that same instance (200, nothing changes). Otherwise this is a
  copy of that instance, in the same organization: create a NEW instance with a new token,
  `previous_instance_id` = the secret's instance, state `pending`, and answer 202. The original
  instance and its token are untouched. If the same copy (copy of the same instance, same
  database name, uuid, stage and neutralized flag; `base_url` aside, an admin login rewrites it)
  already exists, answer that one: an ignored copy stays ignored (410), a pending one
  gets its token back.
- With the enrollment key, whether a new database starts `monitored` (201) or `pending` (202) is
  the organization's policy.
- Dedup (optional, mirrors `host_for_dedup`): a `first_enrollment` whose fingerprint equals an
  active instance of the same organization may get that instance back with a rotated token.
  This covers a module that lost its parameters. Never dedup `fingerprint_changed`, `conflict`
  or `manual`, and never dedup onto an instance that pushed in the last 15 minutes (that
  instance is alive: rotating its token would cut it off).

## 4. Push: `POST /odoo/v1/collect`

One per minute per instance, from the cron, with `Authorization: Bearer <instance token>`.

### Counters and gauges

Two kinds of values travel in a push:

- **Window counters** (everything in `http`, `logs`): what happened during
  `[window.start, window.end]`. Every Odoo process keeps cumulative counters since it started.
  The cron subtracts the snapshot of the last push the server ACKNOWLEDGED. So **a failed push
  loses nothing**: the next one covers a longer window. Rates must be computed as
  `count / window.seconds`, never assumed per minute.
- **Gauges** (`crons`, `database`, `system`, `process`): the state at `sent_at`. Percentages that
  need two samples (CPU) cover `system.sample_interval_seconds` before `sent_at`.

`stream_id` names a counter stream: a random id created with every baseline (enrollment, or
`state.json` lost on a reboot or a container redeploy). `seq` is `1 +` the seq of the last
acknowledged push **of that stream**, and restarts at 1 with a new `stream_id`. Dedup on
`(stream_id, seq)`, never on `seq` alone. A push that failed is resent with the SAME stream and
seq and a longer window. If the server gets a (stream, seq) it already accepted, the module never saw the
answer (timeout after the server processed it): the window overlaps the accepted one. The server
should then accept the gauges and keep only the part of the counters it has not stored yet
(window from the previous `window.end`), or drop the counters of that push. It must answer 200
either way, or the module will keep resending.

`window.baseline_reset = true` means the counters restarted from zero at `window.start`: first
push after an enrollment, or after the module's spool directory was lost (host reboot, `/tmp`
wiped). The counters are correct for the window, but nothing before it was counted.

### Units

- Timestamps: Unix time in seconds, float (`sent_at`, `window.*`, `*_at`, cron `nextcall`).
- Request latency: milliseconds. Other durations: seconds (field names say `_ms` or `_seconds`).
- Sizes: bytes. Percentages: 0-100.

### Body, top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | `1` |
| `sent_at` | float | When the payload was built. |
| `stream_id` | string | See above. |
| `seq` | int >= 1 | See above. |
| `window.start` / `window.end` / `window.seconds` | float | Counter window. |
| `window.baseline_reset` | bool | See above. |
| `instance` | object | The enrollment `instance` object (section 3), plus `instance_id` and `fingerprint_change`. |
| `process` | object or null | Odoo server process (below). |
| `events` | array | Restarts and worker changes (below). |
| `http` | object or null | Requests in the window. `null` = request capture impossible (access logging disabled): unknown, not zero. |
| `logs` | object or null | WARNING / ERROR / CRITICAL in the window. |
| `crons` | object or null | Scheduled actions (gauge). |
| `database` | object or null | PostgreSQL (gauge). |
| `system` | object or null | Host and container (gauge). |
| `collector_errors` | array | `{collector, type, message}` for each collector that failed (its block is then `null` or partial). `message` is at most 200 chars. |

`instance.fingerprint_change` is `null`, or `"base_url_changed"` on every push from the moment
the module adopted a new `web.base.url` until one push is acknowledged (section 5).

### `process`

| Field | Meaning |
|---|---|
| `pid`, `started_at` | Odoo master process (prefork) or server process (threaded). |
| `mode` | `prefork` (workers > 0), `threaded` (workers = 0), `gevent`, or `null` if unknown. |
| `workers` | `[{pid, started_at, last_flush_at}]`: live processes that flushed counters for this database (HTTP workers that served it, the cron worker...). |
| `request_capture` | `native` (the access log is at INFO: the `werkzeug` logger up to Odoo 19.0, `odoo.http.server` from 20.0), `forced` (Odoo runs with `log_level = warn`; the module lowered only the access logger and filtered the other handlers, so the log output is unchanged), `disabled` (then `http` is `null`). |

### `events`

Computed against the last acknowledged push, so an event is resent until the server got it.

| `type` | Fields | Meaning |
|---|---|---|
| `server_restart` | `at` (new start time), `previous` and `current` (`{pid, started_at, mode}`) | The master process changed since the last acknowledged push: restart or redeploy. The previous identity is stored in the database, so this survives a reboot or a new container. |
| `workers_changed` | `at`, `started` (pids), `exited` (pids) | The set of live processes changed: worker recycling (`limit_request`, memory limits) or restart. |

### `http`

Built from the HTTP access log record. Up to Odoo 19.0 that is the `werkzeug` record: status =
`record.args[1]` (Werkzeug 2+; Werkzeug 1.x, e.g. Debian bullseye's in the official `odoo:16`
image, logs the line pre-formatted and the status is parsed from its end), time and SQL from
`record.perf_info` = `query_count query_time remaining_time` (Odoo 12+). Odoo 20.0 serves HTTP
itself (h11): its access line is an INFO record of the `odoo.http.server` logger with
`http_response_status`, `query_count`, `query_time` and `remaining_time` as record attributes.
Total time = `query_time + remaining_time`. Only requests served for THIS database are counted.

| Field | Meaning |
|---|---|
| `requests_total` | Requests in the window. |
| `requests_by_status` | `{"1xx", "2xx", "3xx", "4xx", "5xx", "other"}` counts. |
| `requests_per_minute` | `requests_total * 60 / window.seconds`. `null` when the window is empty. |
| `timed_requests` | Requests that carried a usable `perf_info`. Latency and SQL figures are over these. |
| `latency_ms.p50` / `p95` / `p99` / `mean` | Milliseconds. Percentiles are interpolated in the histogram below. Values above the last bound read as that bound (60000). `null` when `timed_requests = 0`. |
| `latency_histogram.bounds_ms` | Bucket upper bounds: `[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000]`. |
| `latency_histogram.counts` | 14 counts: `counts[i]` = latency in `(bounds[i-1], bounds[i]]`, the last one = above 60 s. Lets the server merge windows and compute its own percentiles. |
| `sql_queries_total`, `sql_time_ms_total` | Sums over timed requests. |
| `sql_queries_per_request`, `sql_time_ms_per_request` | Averages. `null` when `timed_requests = 0`. |

Long-polling and websocket requests are counted like any request.

### `logs`

| Field | Meaning |
|---|---|
| `messages` | `on` (the default) or `off` (an administrator turned "Send error messages" off in Settings). Says whether the `last_*` texts below are sent. |
| `warning_count`, `error_count`, `critical_count` | Records at that level for this database in the window. |
| `fingerprints` | Top 50 ERROR/CRITICAL groups by count: `{fingerprint, count, logger, level, message_template, exception_type, exception_origin, location, last_seen_at, last_message, last_traceback}`. |
| `fingerprints_truncated` | More groups existed (or a process hit its 100-group cap). |

Grouping key: logger, level, the message TEMPLATE (`record.msg` before `%` substitution, so no
argument value ever leaves the instance), exception type, and the innermost
traceback frame (`exception_origin`, `path:line function`) or else the log call site
(`location`). `fingerprint` is 16 hex chars, stable across processes and restarts.
A message formatted before logging (an f-string, `'x %s' % v`, `str(e)`, Werkzeug 1.x lines) has
no template: its values are masked before grouping and sending (emails, URLs, query values,
`Key (col)=(value)`, quoted strings, long hex ids and numbers become `<email>`, `<url>`, `?`,
`=(?)`, `'?'`, `<hex>`, `N`), so its variants also share one fingerprint. A pre-formatted
message longer than 2000 characters is cut: only its text before the first quote or `=(` is kept
(without either, up to the last whitespace before the cut), masked the same way, and ends with
` [cut]`.

The latest occurrence of each group is sent as is, with its values, when `messages` is `on`.
The sample is taken at most once every 10 seconds per group (masking runs under the logging
lock), and one push carries at most 200,000 characters of texts, given to the groups in count
order; the groups past that budget go without texts.

| Field | Meaning |
|---|---|
| `last_seen_at` | When the latest occurrence was logged. Sent in both modes. |
| `last_message` | The formatted message (`record.getMessage()`), at most 2000 chars (cut at a whitespace, ends with `[cut]`). `null` when `messages` is `off` or past the budget. |
| `last_traceback` | The formatted traceback (and stack info), its LAST 8000 chars (starts with `[cut] `), `null` without one, when `messages` is `off` or past the budget. |

Credentials are masked in both texts, always, whatever the switch: `user:password@` in URLs and
DSNs becomes `***:***@`; the value of an `Authorization` header, of a secret-named key
(`password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`,
`session_id`, `signature`, `credentials`, also as a suffix: `smtp_password`, `x-api-key`) after
`=` or `:` becomes `***`; `Bearer <token>` becomes `Bearer ***`; JWTs become `<jwt>`; hex runs of
32+ chars (Fivenines secrets, most API keys) become `<hex>`. The masks are a deny-list with
bounded quantifiers (linear time), applied BEFORE the length cut on a window a little larger
than the bound, so a cut never separates a secret's name from its value: a secret in another
shape (free prose, an unnamed value) is not recognized.

### `crons`

Read with Odoo's own cursor (no extra connection), excluding the module's own job.

| Field | Meaning |
|---|---|
| `active_count` | Active scheduled actions. |
| `due_count` | `nextcall <= now`. |
| `overdue_count` | `nextcall` older than `late_threshold_seconds` (300). |
| `running_count` | Jobs whose `ir_cron` row is locked right now (Odoo holds `FOR NO KEY UPDATE` on a running job). Probed with `SKIP LOCKED` on a separate cursor, never waits. `null` if the probe failed. |
| `late_count` | Overdue and NOT running: nobody picks it up (cron threads saturated or disabled). |
| `stuck_count` | Running and overdue by more than `stuck_threshold_seconds` (1800). |
| `failing_count` | Jobs with `failure_count > 0`. `null` on Odoo 16 and 17 (the field exists from Odoo 18, saas-17.3). |
| `failure_fields_available` | Whether `failure_count` / `first_failure_date` exist. |
| `jobs` | Up to 50 jobs that are late, stuck, running or failing: `{id, name, state, nextcall, lastcall, lateness_seconds, interval, priority, running, failure_count, first_failure_at}`. `state` is one of `late`, `stuck`, `running`, `failing`. |
| `jobs_truncated` | More than 50. |

### `database`

| Field | Meaning |
|---|---|
| `size_bytes` | `pg_database_size(current_database())`. |
| `connections.total` / `active` / `idle` / `idle_in_transaction` / `waiting_on_lock` | `pg_stat_activity` rows for this database. |
| `longest_transaction_seconds` | Oldest open transaction on this database (excluding the module's own). `null` if none. |
| `server_connections_total` | Client backends on the whole PostgreSQL server. |
| `server_max_connections` | `SHOW max_connections`. |
| `odoo_db_maxconn` | Odoo's pool size (`db_maxconn`). |
| `postgresql_version_num` | `SHOW server_version_num`. |

### `system`

| Field | Meaning |
|---|---|
| `host.cpu_count`, `host.cpu_usage_percent` | psutil. The percentage is over all host cores, between two cron runs (`null` on the first run). |
| `host.load_average` | `[1, 5, 15]` minutes. |
| `host.memory_total_bytes`, `memory_available_bytes`, `memory_used_percent`, `swap_total_bytes`, `swap_used_bytes`, `process_count` | psutil, host-wide. In a container this is the HOST: use `cgroup` for the real limits. |
| `cgroup` | `null` when no cgroup is readable. Otherwise: |
| `cgroup.version` | `1` or `2`. |
| `cgroup.path` | Our cgroup path from `/proc/self/cgroup` (`/` in a container namespace; `/system.slice/odoo.service` for a systemd service). |
| `cgroup.cpu_limit_cores` | CPU quota in cores (`cpu.max` or `cfs_quota/period`). `null` = no quota. |
| `cgroup.cpu_usage_percent` | Usage over the sample interval, as a percentage of the quota (or of all host cores without a quota). |
| `cgroup.cpu_throttled_seconds` | Throttled time during the sample interval. |
| `cgroup.memory_usage_bytes`, `memory_working_set_bytes` | Usage, and usage minus inactive file cache (what the OOM killer looks at). |
| `cgroup.memory_limit_bytes`, `memory_unlimited` | Limit in bytes; `null` + `memory_unlimited: true` when there is no limit. |
| `cgroup.pids_current`, `pids_limit` | `pids` controller (`null` limit = `max`). |
| `disk` | `{path, total_bytes, used_bytes, free_bytes, used_percent}` of the partition holding the filestore. |
| `odoo_processes` | `{count, rss_bytes, cpu_usage_percent}` for the Odoo master and all its children. CPU is a percentage of ALL host cores. |
| `sample_interval_seconds` | Time since the previous sample (for the CPU percentages). |

### Responses

| Status | Meaning | Module behaviour |
|---|---|---|
| `200` (any 2xx but 202) | Accepted. Body `{"status": "ok", "state": "monitored"}`; an optional `config` object is reserved for later and ignored today. | Marks the counters as acknowledged, deletes the spool files of dead processes, resets the failure count, clears a `revoked`, `pending` or `ignored` status. |
| `202` | Waiting for approval: nothing was stored. Body `{"status": "pending", "state": "pending", "name": "<display name>", "retry_after": 900}`. | Keeps the credentials, drops the window's counters, checks again after `retry_after` (section 3, "Pending"). |
| `410` | Ignored in Fivenines. Body `{"status": "error", "code": "ignored", "name": "<display name>", "message": "..."}`. | Records `ignored`: no automatic request any more (section 3). |
| `401` | Unknown, revoked or disabled instance token. | Keeps the secret, records `revoked`, stops pushing and tries again once every 24 h ("Send now" tries at once). It never re-enrolls on its own: that would undo the revocation. A later 2xx resumes on the same instance; an administrator's "Re-enroll" starts over as a new instance. A copy of a revoked database (new fingerprint) may enroll. |
| `402` | Subscription inactive. | Keeps the secret, retries in 1 hour. |
| `403` | Instance disabled or refused by policy. | Keeps the secret, retries in 1 hour. |
| `409` | Fingerprint conflict: this token is in use from another location (section 5). | Announces itself at once with the same secret: `/enroll` with `credential: "instance_secret"`, `reason: "conflict"` and `previous_instance_id`. The server treats it as a copy (new pending instance). |
| `400` / `413` / `422` | Payload refused. | Bounded backoff. The counters are kept (the window grows), warning logged at most every 15 min. Put a short reason in `message`. |
| `429` | Rate limited. | Waits `Retry-After` (capped at 1 hour), else 60 s. |
| `404`, `5xx`, timeout, connection error | Transient. | Bounded backoff (section 7). |

## 5. Fingerprint and copies

The module compares the current fingerprint with the one stored at enrollment, before every run
(before any backoff, so a copy never waits for the original's retry schedule):

- **Equal**: push.
- **Only `base_url` changed**: Odoo rewrites `web.base.url` on every administrator login
  (unless `web.base.url.freeze` is set), so this is a first login from the real URL or an alias
  (a LAN IP, a second domain), not a copy. The module adopts the new fingerprint, keeps its
  secret and sends `instance.fingerprint_change = "base_url_changed"` on every push until one is
  acknowledged.
- **The database name, `database.uuid`, `ODOO_STAGE` or `neutralized` changed**: the database
  was copied (staging from production, a restore under another name, Odoo's duplicate which
  regenerates the uuid, a neutralized copy). Before any push, the module announces itself to
  `/enroll` with the secret it carries (`credential: "instance_secret"`,
  `reason: "fingerprint_changed"`, `changed`, `previous_instance_id`), without waiting for the
  original's backoff (its own failed announcements back off, section 7). The
  server mints a new secret for a new, proposed (pending) database; the copy stores it and the
  copied secret is gone. Until that succeeds the copy pushes nothing with the copied secret.
  Production keeps its own secret, so the two never report as one.
- **Neutralized copies** (Odoo.sh staging/dev, `odoo-bin neutralize`, neutralized duplicates):
  the module adds nothing to Odoo's neutralization, so the copy keeps the secret, the instance id
  and the fingerprint. Neutralization deactivates every cron, ours included (the cron record is
  `noupdate`, so an upgrade does not re-activate it), and the module never re-activates it by
  itself. The copy's settings screen says "This database is a neutralized copy: monitoring is
  off" with a "Turn it on" button that re-activates the push cron. The next run sees
  `neutralized` changed and announces the copy as above.

Server side, the "409 rule" decides what the module cannot see (two live places with the same
database name and uuid: a PostgreSQL-level copy on another server). The server stores, per
instance, the fingerprint and the identity of the last accepted push: `instance.hostname`,
`process.pid` and `process.started_at`. When a push carries a fingerprint different from the
stored one:

1. same identity as the last accepted push (the same running server changed its URL): adopt it.
   Also adopt it when the instance has no accepted push yet (nobody else used the token);
2. otherwise, **answer 409, whatever the time since the last accepted push**. The module that
   gets it announces itself with the token (`reason: "conflict"`), and the server always
   creates a new pending instance for it: a copy is proposed, never added. The server never
   adopts a new place on its own, even after a silence: a production database restored on a
   test server while production is down must not take over production's identity.

A move is never guessed. The administrator who knows a proposal is a move says so on the
proposal ("Replaces an existing database"); until then the two stay apart.

Consequence: a URL change seen with another identity (the first push after a restart that also
changed `web.base.url`, or from a second node) becomes a proposal too. The module cannot tell
those cases from a copy; the administrator's choice on the proposal resolves them.

`fingerprint_change` is informational (show "URL changed"); it never bypasses this rule. A copy
whose fingerprint and identity both equal the original's cannot be told apart by anyone: it is
treated as the same instance.

## 6. Security

- The enrollment key and the instance token travel only in the `Authorization` header, over
  HTTPS. They are never put in a URL, a payload, a log line or an error message. The module's
  tests check that neither appears in any log record nor in any payload.
  Exception outside the module's control: with `log_level = debug_sql`, Odoo itself logs every
  SQL statement with its values, including the `ir.config_parameter` row that holds the token.
- The token is stored in `ir.config_parameter` (`fivenines.instance_secret`), readable by
  administrators only. The settings screen never displays it.
- The server must not log the `Authorization` header (Rails `filter_parameters` does not cover
  headers; check the request logging).
- **The payload carries error messages and tracebacks by default** (`logs.messages = "on"`,
  section 4): they can contain customer data (a partner name, an order reference, a value from a
  failed constraint). An administrator can turn them off in Settings ("Send error messages");
  the push then carries only groups and counts (`messages: "off"`). Credentials are masked in
  every message and traceback in both modes (section 4). The rest of the payload is message
  templates, cron names, URLs, counts and sizes.

## 7. Retry and backoff (module side)

The cron runs every minute and does not hang on a slow answer: one run makes at most four
requests (a copy's announcement, an enrollment with the key when that secret is refused, a push,
and an announcement after a 409), each with a 10 s timeout on the
connection and on every read (requests' timeout is per read, not a total deadline: a server
that trickles bytes can hold a run longer; on prefork servers `limit_time_real` still kills the
cron worker). It never raises (Odoo 18+ deactivates a cron that keeps failing), and each SQL
collector runs in a savepoint, so a failing query only nulls its block.

After a retryable failure (`404`, `5xx`, `400`/`413`/`422`, timeout, connection error):

| Consecutive failures | Next attempt |
|---|---|
| 1, 2, 3 | next minute |
| 4 | +2 min |
| 5 | +4 min |
| 6 | +8 min |
| 7 and more | +15 min (cap) |

`429` uses `Retry-After`; `402`/`403` wait 1 hour; `401` waits 24 hours; `202` (pending) waits
`retry_after` (default 15 min, 5 min to 6 h); `410` (ignored) stops; `409` announces the copy at
once. A copy announces itself without waiting for the original's backoff; a failed announcement
(`404`, `5xx`, timeout...) then follows this same bounded backoff, so copies do not call
`/enroll` every minute while Fivenines is down. A success resets the count. During the backoff the counters keep accumulating: nothing is lost
unless the Odoo processes die AND their spool files are wiped before the next successful push.

## 8. Module-side storage (for reference)

| Where | What |
|---|---|
| `ir.config_parameter` | `fivenines.enrollment_key` (if pasted in Settings, deleted once an enrollment succeeds), `fivenines.api_url`, `fivenines.paused`, `fivenines.error_messages_off`, `fivenines.instance_secret`, `fivenines.instance_id`, `fivenines.endpoint` (the API URL that issued the secret), `fivenines.fingerprint` (hash + components), `fivenines.enrolled_at`, `fivenines.status` (`pending` / `ignored` with the server's name, `revoked`, `enrollment_refused`, `copy_needs_key`), `fivenines.server_identity` (last acknowledged master pid + start time). Written rarely: every write invalidates the ORM caches of all workers. On Odoo 20.0 they go through the typed `get_str`/`set_str` API. |
| `<tmp>/fivenines-<uid>/<db>-<hash8>/<pid>-<start>.json` | Cumulative counters of one Odoo process, flushed every 10 s and at exit (atomic rename). |
| same dir, `state.json` | Acknowledged baselines, `stream` and `seq`, backoff, a pending enrollment reason, a pending `fingerprint_change`, last result. `state.lock` serializes pushes (flock). |

`<hash8>` = sha1 of `db_host:db_port:dbname`, so two Odoo servers on one machine with the same
database name do not mix. `<pid>-<start>` keeps a dead process's last counters from being
overwritten by a new process that got the same pid (common in containers). A file is deleted
only once its process is dead (pid gone, or another start time) and its last counters were
acknowledged; a live worker keeps its file however long it has been idle.

## 9. Implementing the server side (checklist for the fivenines-server PR)

1. Routes `POST /odoo/v1/enroll` and `POST /odoo/v1/collect` (API host, JSON, gzip inflate, body
   cap after inflation).
2. A model for Odoo instances (or `Host` with a new `source`), belonging to an organization and
   to the `EnrollmentToken` that created it: `instance_id` (public string), `token` (unique,
   `SecureRandom.hex(32)`), `state` (`monitored`, `pending`, `ignored`), `revoked_at`,
   `disabled`, fingerprint hash + components, `previous_instance_id`, `urls`, `last_push_at`,
   `last_identity` (hostname, pid, started_at), `last_stream_id`, `last_seq`,
   `last_window_end`.
3. Enrollment: section 3 (key or a copy's secret; 201 / 202 / 410 / 401 / 402 / 403,
   `hosts_registered_count`, `last_used_at`, uptime monitors matched on `urls`).
4. Collect: authenticate by token (401), ignored (410), pending (202, store nothing),
   subscription (402), 409 rule (section 5: never adopt another identity on silence alone),
   validate against the schema (422 with a short
   `message`), dedup by `(stream_id, seq)` (section 4), store, 200.
5. UI: list instances under the organization, Monitor / Ignore a pending one, "Replaces an
   existing database" on a proposal (section 5; never guessed), revoke one, show
   "copied from" via `previous_instance_id`, show `server_restart` as an event, not as a gap,
   show `last_message` / `last_traceback` per error group.
6. Contract tests: post the stub's fixtures (`tests/schemas`) and the payloads the module's
   tests produce.

## 10. The stub

```sh
python3 fivenines_monitoring/tests/stub_server.py --port 8899 \
    --enrollment-key "$(openssl rand -hex 32)" --log-file /tmp/pushes.jsonl
```

It implements sections 3 to 5 (including the 409 rule, copies announced with a secret, pending
and ignored), validates both bodies against the schemas (422 on drift), and offers test-only
endpoints on loopback: `GET /_stub/state`, `POST /_stub/revoke {"instance_id"}`,
`POST /_stub/revoke_key {"key"}`, `POST /_stub/fail {"status", "count", "path", "retry_after"}`,
`POST /_stub/accept {"instance_id"}` (Monitor a pending database),
`POST /_stub/ignore {"instance_id"}` (Ignore it), `POST /_stub/policy {"new", "retry_after"}`
(new databases start `monitored` or `pending`; the pending check interval),
`POST /_stub/reset`.

## 11. Revisions

- **v1, revision 2** (fivenines_odoo #3-#7, before any server shipped, so `schema_version` stays
  `1`): Odoo 20.0 (access log from `odoo.http.server`); the key is used once and not kept; copies
  announce themselves with the copied secret (`credential`, `changed`, the `neutralized`
  component; `neutralize.sql` and the `neutralized_copy` reason are gone, neutralization is
  respected and "Turn it on" is one click); pending (`202`) and ignored (`410`) on both
  endpoints; `instance.urls`; error messages and tracebacks by default with `logs.messages`,
  credentials always masked; a 409 is answered with a copy announcement; the 409 rule never
  adopts another place on silence (rule 3 removed): it proposes it, and a move is never
  guessed; failed copy announcements back off.
