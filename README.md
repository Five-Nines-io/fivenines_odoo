# Fivenines Monitoring for Odoo

`fivenines_monitoring` brings the equivalent of the Odoo.sh "Monitor" tab to any Odoo 16, 17, 18
or 19, Community or Enterprise, Odoo.sh or self-hosted. Add the module, paste a Fivenines
enrollment key, done: every minute the instance pushes its own metrics to Fivenines over HTTPS.
Nothing to open on the firewall, no agent to run.

- **Requests**: requests per minute by status class, p50 / p95 / p99 latency, SQL queries and
  SQL time per request. Each database counts only its own requests, even on a multi-database
  server.
- **Errors**: ERROR and CRITICAL counts, grouped by fingerprint (logger, message template,
  exception type and origin). No customer data: message templates, never formatted messages.
- **Scheduled actions**: late, stuck, running and (Odoo 18+) failing crons.
- **Database**: size, connections by state, longest transaction, server connection usage.
- **System**: CPU, memory, disk, Odoo processes, with the real container limits from cgroup
  v1/v2 when there are some.
- **Restarts**: a new master process or a changed worker set is reported as an event, not a gap.

Design and open questions: issue #1. The wire format is in [docs/api-contract.md](docs/api-contract.md).

## Install

### Self-hosted (Debian/Ubuntu package, Docker, source)

1. Put the `fivenines_monitoring` directory in an addons directory and add that directory to
   `addons_path` in the Odoo config file (e.g. `/etc/odoo/odoo.conf`).
2. Restart Odoo, then Apps > Update Apps List > search "Fivenines Monitoring" > Activate.
3. Settings > Fivenines Monitoring: paste the enrollment key, Save. The first run (within a
   minute) enrolls the instance. "Send now" pushes immediately.

### Odoo.sh

Add this repository as a Git submodule of your Odoo.sh repository, push, then install the module
and paste the key, in each branch (production, staging, development) you want to monitor. See
"Odoo.sh notes" below.

## Configuration

| What | Settings screen (per database) | Odoo config file `[options]` (server-wide) | Environment |
|---|---|---|---|
| Enrollment key | "Fivenines enrollment key" | `fivenines_enrollment_key` | `FIVENINES_ENROLLMENT_KEY` |
| API URL (default `https://api.fivenines.io`) | "Fivenines API URL" (developer mode) | `fivenines_api_url` | `FIVENINES_API_URL` |
| Pause this database | "Pause monitoring" | - | - |
| Allow plain `http://` API URLs (testing only) | - | `fivenines_allow_insecure_http = True` | `FIVENINES_ALLOW_INSECURE_HTTP` |
| Keep counting requests with `log_level = warn` (default on) | - | `fivenines_capture_quiet_werkzeug` | `FIVENINES_CAPTURE_QUIET_WERKZEUG` |
| Spool directory (default `<tmp>/fivenines-<uid>`) | - | `fivenines_spool_dir` | `FIVENINES_SPOOL_DIR` |

The most specific value wins: Settings, then the config file, then the environment. A key in
the config file or the environment ships with your deployment and enrolls every database that has
the module installed (use "Pause monitoring" to exclude one). Odoo 19 prints one "unknown option"
warning per `fivenines_*` option at startup: it is harmless, Odoo keeps the value.

## How it works

- A logging handler in every Odoo process counts the `werkzeug` access lines (status code and
  Odoo's `perf_info`: SQL count, SQL time, other time) and the WARNING/ERROR/CRITICAL records,
  per database (`threading.current_thread().dbname`).
- Each process flushes its cumulative counters every 10 s to
  `<tmp>/fivenines-<uid>/<db>-<hash>/<pid>-<start>.json` (atomic rename).
- A scheduled action ("Fivenines: push metrics", every minute) sums the files, subtracts what
  Fivenines already acknowledged, adds crons, database and system gauges, and pushes. Files of
  dead processes are removed after their last counters were delivered. When Fivenines cannot be
  reached nothing is lost: the next push covers the longer window. Retries back off up to 15 min.
- The enrollment key is exchanged once for a per-instance secret, stored in
  `ir.config_parameter` (administrators only). A fingerprint of where the database runs (name,
  `database.uuid`, `web.base.url`, Odoo.sh stage) is checked on every run: a copied database
  enrolls as a new instance instead of reporting as the original. Odoo's neutralization also
  deletes the secret.
- Secrets travel only in the `Authorization` header, over HTTPS, and are never logged.

## Odoo.sh notes

- Per the Odoo.sh FAQ (quoted in issue #1), scheduled actions on staging and development branches
  run only a few times a day, and Odoo's neutralization deactivates every scheduled action of a
  neutralized copy. Monitoring of staging/dev is best-effort. The production cadence and
  lateness under load are not verified on Odoo.sh yet.
- Each branch is its own database with its own fingerprint (`ODOO_STAGE` and the database name
  differ), so production and its copies never mix.

## Limitations

- Several Odoo servers sharing one database on different machines: each machine only sees its own
  workers' counters (the spool directory is local), and the cron runs on one of them at a time.
- With `log_level = debug_sql` Odoo itself logs every SQL statement with its values, including
  the row that stores the secret. Do not run production at that level.

## Development

```sh
# tests (Odoo test framework), e.g. Odoo 19 from source
odoo-bin -d fn_test -i fivenines_monitoring --test-tags=/fivenines_monitoring --stop-after-init \
  --addons-path=<odoo>/addons,<this repo>

# the stub server of the Fivenines API
python3 fivenines_monitoring/tests/stub_server.py --port 8899 --enrollment-key <64 hex chars>

# end-to-end on a real server: workers=0, workers=2 with two databases, a copied database
python3 tools/e2e_local.py --odoo-bin <odoo>/odoo-bin --python <venv>/bin/python \
  --addons-path <odoo>/addons --db-user $USER
```

CI (`.github/workflows/ci.yml`) runs the tests on Odoo 16, 17, 18 and 19 with the official Docker
images and PostgreSQL 16. A manual `publish` job builds the `16.0`-`19.0` branches for the Odoo
Apps Store (dry run by default).

## License

LGPL-3. See `LICENSE`.
