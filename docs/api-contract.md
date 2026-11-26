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
  used. This mirrors how the agent works today (`ApiController#authenticate_host!` and
  `#enroll_host_via_token`): an `EnrollmentToken` (`SecureRandom.hex(32)`, revocable,
  `hosts_registered_count`, `last_used_at`) is swapped for a per-host `client_token`. The
  difference is that the Odoo module has a dedicated enrollment call instead of the agent's
  "first `/collect` carries the enrollment token and the answer carries `token`" swap. That keeps
  the enrollment key out of every metrics request.
- **Revocation.** Revoking an instance secret cuts that instance only. The module stops and does
  NOT re-enroll on its own. Revoking the enrollment key blocks new enrollments only.
- **Copies re-enroll.** The module sends a location fingerprint. When it changes, the module drops
  its secret and enrolls as a new instance (section 5).
- **Unknown is `null`, never `0`.** A `0` in a payload is a measurement. Anything the module could
  not measure is `null` (or the whole block is `null`), and the reason may appear in
  `collector_errors`.

## 2. Transport

| | |
|---|---|
| Base URL | `https://api.fivenines.io` (overridable in the module, see the README) |
| Paths | `POST /odoo/v1/enroll`, `POST /odoo/v1/collect` |
| TLS | HTTPS only. The module refuses a plain `http://` URL except on loopback (the stub) or when `fivenines_allow_insecure_http = True` is set in the Odoo config file. |
| Timeout | The module waits 10 s for the connection and 10 s per read, then gives up until the next minute. |
| Redirects | Not followed. Answer at the URL. |

### Request headers

| Header | Value |
|---|---|
| `Authorization` | `Bearer <enrollment key>` on `/enroll`, `Bearer <instance token>` on `/collect`. The ONLY place a credential appears: never in the URL or the body. The server reads it like `ApiController#client_token`: last space-separated word. |
| `Content-Type` | `application/json` |
| `Content-Encoding` | `gzip`. The module always compresses. The server must inflate (the agent API already does this in its middleware) and apply its body cap AFTER inflation. 2 MB is plenty: a real push is 3-30 KB of JSON before compression. |
| `Accept` | `application/json` |
| `User-Agent` | `fivenines-odoo/<module version> (Odoo <release.version>; Python <x.y.z>)`, e.g. `fivenines-odoo/19.0.1.0.0 (Odoo 19.0; Python 3.12.3)` |

### Response format

JSON object. Success: `{"status": "ok", ...}`. Error: `{"status": "error", "message": "..."}`, the
envelope `/collect` already uses for agents. The module logs `message` (truncated to 300 chars)
and shows it on its settings screen, so it must never contain a secret.

## 3. Enrollment: `POST /odoo/v1/enroll`

Sent when the instance has no secret: on the first run after a key is configured, after a
fingerprint change, after a 409, or when an administrator clicks "Re-enroll".

### Request body

```json
{
  "schema_version": 1,
  "reason": "first_enrollment",
  "previous_instance_id": null,
  "key_source": "settings",
  "instance": {
    "fingerprint": "42de0bada0db23b95ee55cbcbc7fa9f9b938cbf9b64c8c83cb8ab776cd78eb13",
    "fingerprint_components": {
      "database": "odoo",
      "database_uuid": "69bc4150-e9e8-11f1-9a52-06616917c26d",
      "base_url": "https://odoo.example.com",
      "odoo_stage": null
    },
    "database": "odoo",
    "database_uuid": "69bc4150-e9e8-11f1-9a52-06616917c26d",
    "base_url": "https://odoo.example.com",
    "odoo_stage": null,
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
| `reason` | `first_enrollment`, `fingerprint_changed` (section 5), `conflict` (after a 409), `manual` ("Re-enroll" button). |
| `previous_instance_id` | The instance this database reported as before. `null` on a first enrollment. Lets the server show "copied from X" or offer to merge a move. |
| `key_source` | Where the module found the key: `settings` (this database), `odoo.conf`, `environment`. |
| `instance.fingerprint` | sha256 hex of the canonical JSON (sorted keys, `json.dumps(..., sort_keys=True)`) of `fingerprint_components`. |
| `instance.fingerprint_components.database` | PostgreSQL database name. |
| `instance.fingerprint_components.database_uuid` | `ir.config_parameter` `database.uuid`. |
| `instance.fingerprint_components.base_url` | `web.base.url`, normalized: lowercase scheme and host, default port dropped, trailing `/` dropped. |
| `instance.fingerprint_components.odoo_stage` | The `ODOO_STAGE` environment variable (`production`, `staging`, `dev` on Odoo.sh). `null` when self-hosted. |
| `instance.odoo_version` / `odoo_serie` / `odoo_version_info` | `odoo.release.version`, `.serie`, `.version_info`. Enterprise builds look like `17.0+e`. |
| `instance.edition` | `enterprise` when `web_enterprise` is installed, else `community`. |
| `instance.module_version` | Manifest version of the module, e.g. `19.0.1.0.0`. |
| `instance.workers`, `max_cron_threads` | From the Odoo config. `workers = 0` means threaded mode. |

The `base_url` is the public URL: the server may offer to create an uptime monitor on it at
enrollment (the issue's install flow, step 4).

### Responses

| Status | Body | Module behaviour |
|---|---|---|
| `201` (any 2xx) | `{"status": "ok", "instance_id": "<string>", "token": "<secret>", "name": "<display name>"}` | Stores `token` and `instance_id` in `ir.config_parameter` (admins only), committed on their own cursor so a rolled-back transaction cannot cause a double enrollment, then pushes in the same run. A 2xx without `token` or `instance_id` is treated as a retryable failure. |
| `401` | invalid or revoked enrollment key | Remembers the refused key (as a hash) and makes no more requests until the key changes or an admin clicks a button. |
| `402` | organization subscription inactive (same meaning as `/collect` today) | Retries in 1 hour. |
| `403` | instance limit reached (`PlanFeatures#instances_limit_reached?`) | Retries in 1 hour. |
| `422` / `400` / `413` | payload refused (contract drift) | Bounded backoff (section 7), warning logged at most every 15 min. |
| `429` | rate limited | Waits `Retry-After` seconds (capped at 1 hour), else 60 s. |
| `404`, `5xx`, timeout, connection error | not deployed yet / transient | Bounded backoff (section 7). |

Server notes:

- Look the key up like `EnrollmentToken.active.lock.find_by(token:)`, bump
  `hosts_registered_count` and `last_used_at`, and refuse with 401 when it is unknown or revoked.
  The same organization key can serve agents and Odoo instances: the issue asks for "one
  enrollment key per Fivenines organization".
- `token`: `SecureRandom.hex(32)`, unique, revocable on its own, like `Host#client_token`.
- Store the fingerprint (hash + components) on the instance (needed for the 409 rule).
- Dedup (optional, mirrors `host_for_dedup`): a `first_enrollment` whose fingerprint equals an
  active instance of the same organization may get that instance back with a rotated token.
  This covers a module that lost its parameters. Never dedup `fingerprint_changed`, `conflict` or
  `manual`.

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

`seq` is `1 +` the seq of the last acknowledged push. A push that failed is resent with the SAME
seq and a longer window. If the server gets a seq it already accepted, the module never saw the
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
| `seq` | int >= 1 | See above. |
| `window.start` / `window.end` / `window.seconds` | float | Counter window. |
| `window.baseline_reset` | bool | See above. |
| `instance` | object | The enrollment `instance` object (section 3), plus `instance_id` and `fingerprint_change`. |
| `process` | object or null | Odoo server process (below). |
| `events` | array | Restarts and worker changes (below). |
| `http` | object or null | Requests in the window. `null` = request capture impossible (werkzeug logging disabled): unknown, not zero. |
| `logs` | object or null | WARNING / ERROR / CRITICAL in the window. |
| `crons` | object or null | Scheduled actions (gauge). |
| `database` | object or null | PostgreSQL (gauge). |
| `system` | object or null | Host and container (gauge). |
| `collector_errors` | array | `{collector, type, message}` for each collector that failed (its block is then `null` or partial). `message` is at most 200 chars. |

`instance.fingerprint_change` is `null`, or `"base_url_from_loopback"` when the module adopted a
new `web.base.url` because the old one was `localhost`/`127.x` (section 5).

### `process`

| Field | Meaning |
|---|---|
| `pid`, `started_at` | Odoo master process (prefork) or server process (threaded). |
| `mode` | `prefork` (workers > 0), `threaded` (workers = 0), `gevent`, or `null` if unknown. |
| `workers` | `[{pid, started_at, last_flush_at}]`: live processes that flushed counters for this database (HTTP workers that served it, the cron worker...). |
| `request_capture` | `native` (werkzeug access log at INFO), `forced` (Odoo runs with `log_level = warn`; the module lowered only the `werkzeug` logger and filtered the other handlers, so the log output is unchanged), `disabled` (then `http` is `null`). |

### `events`

Computed against the last acknowledged push, so an event is resent until the server got it.

| `type` | Fields | Meaning |
|---|---|---|
| `server_restart` | `at` (new start time), `previous` and `current` (`{pid, started_at, mode}`) | The master process changed since the last acknowledged push: restart or redeploy. The previous identity is stored in the database, so this survives a reboot or a new container. |
| `workers_changed` | `at`, `started` (pids), `exited` (pids) | The set of live processes changed: worker recycling (`limit_request`, memory limits) or restart. |

### `http`

Built from the `werkzeug` access log record: status = `record.args[1]` (Werkzeug 2+; Werkzeug
1.x, e.g. Debian bullseye's in the official `odoo:16` image, logs the line pre-formatted and the
status is parsed from its end), time and SQL from
`record.perf_info` = `query_count query_time remaining_time` (Odoo 12+). Total time =
`query_time + remaining_time`. Only requests served for THIS database are counted.

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
| `warning_count`, `error_count`, `critical_count` | Records at that level for this database in the window. |
| `fingerprints` | Top 50 ERROR/CRITICAL groups by count: `{fingerprint, count, logger, level, message_template, exception_type, exception_origin, location}`. |
| `fingerprints_truncated` | More groups existed (or a process hit its 100-group cap). |

Grouping key: logger, level, the message TEMPLATE (`record.msg` before `%` substitution, so no
argument value and no customer data ever leaves the instance), exception type, and the innermost
traceback frame (`exception_origin`, `path:line function`) or else the log call site
(`location`). `fingerprint` is 16 hex chars, stable across processes and restarts.

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
| `200` (any 2xx) | Accepted. Body `{"status": "ok"}`; an optional `config` object is reserved for later and ignored today. | Marks the counters as acknowledged, deletes the spool files of dead processes, resets the failure count. |
| `401` | Unknown, revoked or disabled instance token. | Drops the secret, records `revoked`, stops. Neither the cron nor "Send now" re-enrolls: re-enrolling on its own would undo the revocation. Only an administrator's "Re-enroll" resumes. A copy of a revoked database (new fingerprint) may enroll. |
| `402` | Subscription inactive. | Keeps the secret, retries in 1 hour. |
| `403` | Instance disabled or refused by policy. | Keeps the secret, retries in 1 hour. |
| `409` | Fingerprint conflict: this token is in use from another location (section 5). | Drops the secret and enrolls again at once, with `reason: "conflict"` and `previous_instance_id`. |
| `400` / `413` / `422` | Payload refused. | Bounded backoff. The counters are kept (the window grows), warning logged at most every 15 min. Put a short reason in `message`. |
| `429` | Rate limited. | Waits `Retry-After` (capped at 1 hour), else 60 s. |
| `404`, `5xx`, timeout, connection error | Transient. | Bounded backoff (section 7). |

## 5. Fingerprint and copies

The module compares the current fingerprint with the one stored at enrollment, before every run:

- **Equal**: push.
- **Only `base_url` changed, and the stored one was loopback** (`localhost`, `127.x`, `::1`,
  empty): the same instance after its first admin login (Odoo rewrites `web.base.url` then).
  The module adopts the new fingerprint, keeps its secret and sends
  `instance.fingerprint_change = "base_url_from_loopback"` once.
- **Anything else changed** (database name, `database.uuid`, public URL, `ODOO_STAGE`): the
  database was copied (staging from production, a restore elsewhere) or moved. The module drops
  the copied secret and enrolls with `reason: "fingerprint_changed"` and `previous_instance_id`.
  Production keeps its own secret, so the two never report as one.
- Odoo's neutralization (Odoo.sh staging/dev copies, `odoo-bin neutralize`, neutralized
  duplicates) also deletes the module's secret (`data/neutralize.sql`), and it deactivates every
  cron, ours included.

Server-side safety net (the "409 rule"): the server stores the fingerprint of each instance.
It **must answer 409** when a push carries a fingerprint different from the stored one **and**
the stored fingerprint pushed within the last 15 minutes: one token, two live places. Otherwise
(the old place has been silent for 15 minutes, a move) it may adopt the new fingerprint. It must
always adopt it when `fingerprint_change = "base_url_from_loopback"`. A copy whose fingerprint
equals the original's (a byte-identical restore with the same name, uuid and URL) cannot be told
apart by anyone: it is treated as the same instance.

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
- The payload carries no customer data by design: log message templates, not formatted
  messages; cron names; counts and sizes.

## 7. Retry and backoff (module side)

The cron runs every minute and never blocks: one run makes at most two requests (enroll + push,
or push + re-enroll after a 409), each bounded by the 10 s timeout. It never raises (Odoo 18+
deactivates a cron that keeps failing).

After a retryable failure (`404`, `5xx`, `400`/`413`/`422`, timeout, connection error):

| Consecutive failures | Next attempt |
|---|---|
| 1, 2, 3 | next minute |
| 4 | +2 min |
| 5 | +4 min |
| 6 | +8 min |
| 7 and more | +15 min (cap) |

`429` uses `Retry-After`; `402`/`403` wait 1 hour; `401` stops; `409` re-enrolls at once. A
success resets the count. During the backoff the counters keep accumulating: nothing is lost
unless the Odoo processes die AND their spool files are wiped before the next successful push.

## 8. Module-side storage (for reference)

| Where | What |
|---|---|
| `ir.config_parameter` | `fivenines.enrollment_key` (if set in Settings), `fivenines.api_url`, `fivenines.paused`, `fivenines.instance_secret`, `fivenines.instance_id`, `fivenines.fingerprint` (hash + components), `fivenines.enrolled_at`, `fivenines.status` (revoked / enrollment refused), `fivenines.server_identity` (last acknowledged master pid + start time). Written rarely: every write invalidates the ORM caches of all workers. |
| `<tmp>/fivenines-<uid>/<db>-<hash8>/<pid>-<start>.json` | Cumulative counters of one Odoo process, flushed every 10 s and at exit (atomic rename). |
| same dir, `state.json` | Acknowledged baselines, `seq`, backoff, last result. `state.lock` serializes pushes (flock). |

`<hash8>` = sha1 of `db_host:db_port:dbname`, so two Odoo servers on one machine with the same
database name do not mix. `<pid>-<start>` keeps a dead process's last counters from being
overwritten by a new process that got the same pid (common in containers).

## 9. Implementing the server side (checklist for the fivenines-server PR)

1. Routes `POST /odoo/v1/enroll` and `POST /odoo/v1/collect` (API host, JSON, gzip inflate, body
   cap after inflation).
2. A model for Odoo instances (or `Host` with a new `source`), belonging to an organization and
   to the `EnrollmentToken` that created it: `instance_id` (public string), `token` (unique,
   `SecureRandom.hex(32)`), `revoked_at`, `disabled`, fingerprint hash + components,
   `previous_instance_id`, `last_push_at`, `last_seq`, `last_window_end`.
3. Enrollment: section 3 (401 / 402 / 403 like `/collect`, `hosts_registered_count`,
   `last_used_at`, optional uptime monitor on `base_url`).
4. Collect: authenticate by token (401), subscription (402), 409 rule (section 5), validate
   against the schema (422 with a short `message`), dedup by `seq` (section 4), store, 200.
5. UI: list instances under the organization, revoke one, show "copied from" via
   `previous_instance_id`, show `server_restart` as an event, not as a gap.
6. Contract tests: post the stub's fixtures (`tests/schemas`) and the payloads the module's
   tests produce.

## 10. The stub

```sh
python3 fivenines_monitoring/tests/stub_server.py --port 8899 \
    --enrollment-key "$(openssl rand -hex 32)" --log-file /tmp/pushes.jsonl
```

It implements sections 3 to 5 (including the 409 rule), validates both bodies against the
schemas (422 on drift), and offers test-only endpoints on loopback: `GET /_stub/state`,
`POST /_stub/revoke {"instance_id"}`, `POST /_stub/revoke_key {"key"}`,
`POST /_stub/fail {"status", "count", "path", "retry_after"}`, `POST /_stub/reset`.
