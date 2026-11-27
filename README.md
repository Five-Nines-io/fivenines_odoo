# Fivenines Monitoring for Odoo

`fivenines_monitoring` brings the equivalent of the Odoo.sh "Monitor" tab to any Odoo 16, 17, 18,
19 or 20, Community or Enterprise, Odoo.sh or self-hosted. Add the module, paste a Fivenines
enrollment key, done: every minute the instance pushes its own metrics to Fivenines over HTTPS.
Nothing to open on the firewall, no agent to run.

- **Requests**: requests per minute by status class, p50 / p95 / p99 latency, SQL queries and
  SQL time per request. Each database counts only its own requests, even on a multi-database
  server.
- **Errors**: ERROR and CRITICAL counts, grouped by fingerprint (logger, message template,
  exception type and origin), with the latest message and traceback of each group. Messages
  and tracebacks can contain business data (a partner name, an order reference); turn them off
  with "Send error messages" in Settings. Credentials are masked in them either way.
- **Scheduled actions**: late, stuck, running and (Odoo 18+) failing crons.
- **Database**: size, connections by state, longest transaction, server connection usage.
- **System**: CPU, memory, disk, Odoo processes, with the real container limits from cgroup
  v1/v2 when there are some.
- **Restarts**: a new master process or a changed worker set is reported as an event, not a gap.

Design and open questions: issue #1. The wire format is in [docs/api-contract.md](docs/api-contract.md).

## Install

### Self-hosted (Debian/Ubuntu package, Docker, source)

One zip serves every Odoo version, 16 to 20:
[fivenines_monitoring.zip](https://github.com/Five-Nines-io/fivenines_odoo/releases/latest/download/fivenines_monitoring.zip)
(the latest release; each release also carries `fivenines_monitoring-<version>.zip` and `SHA256SUMS`).

1. Unpack the zip into an addons directory (it holds one `fivenines_monitoring/` directory) and
   add that directory to `addons_path` in the Odoo config file (e.g. `/etc/odoo/odoo.conf`).
   For example: `sudo mkdir -p /opt/odoo-addons && sudo python3 -m zipfile -e
   fivenines_monitoring.zip /opt/odoo-addons`, then `addons_path = ...,/opt/odoo-addons`.
2. Restart Odoo, then Apps > Update Apps List > search "Fivenines Monitoring" > Activate.
3. Settings > Fivenines Monitoring: paste the enrollment key, Save. The first run (within a
   minute) enrolls the instance. "Send now" pushes immediately. The key is used once: after the
   enrollment it is deleted from the database, and the instance keeps only its own secret.
4. If your organization approves new databases, the settings screen says "Waiting for approval
   in Fivenines as <name>" until someone clicks Monitor (or Ignore) in Fivenines.

### Odoo.sh

Add this repository as a Git submodule of your Odoo.sh repository, pinned to a release tag (the
same tree works on every Odoo version, so the tag does not depend on your branch's version):

```sh
git submodule add https://github.com/Five-Nines-io/fivenines_odoo.git fivenines_odoo
git -C fivenines_odoo checkout v1.0        # the latest release tag
git add .gitmodules fivenines_odoo && git commit -m "Add Fivenines Monitoring" && git push
```

Odoo.sh adds the submodule to the addons path. Install the module and paste the key in each
branch (production, staging, development) you want to monitor. To upgrade, check out the newer
tag in the submodule, commit and push; Odoo.sh updates the module. See "Odoo.sh notes" below.

### Upgrading

Replace the `fivenines_monitoring` directory with the one from the newer zip (or move the
submodule to the newer tag), then upgrade the module: Apps > Fivenines Monitoring > Upgrade, or
`odoo-bin -u fivenines_monitoring -d <database> --stop-after-init`.

## Configuration

| What | Settings screen (per database) | Odoo config file `[options]` (server-wide) | Environment |
|---|---|---|---|
| Enrollment key | "Fivenines enrollment key" | `fivenines_enrollment_key` | `FIVENINES_ENROLLMENT_KEY` |
| API URL (default `https://api.fivenines.io`) | "Fivenines API URL" (developer mode) | `fivenines_api_url` | `FIVENINES_API_URL` |
| Pause this database (Fivenines then shows it as Paused: a heartbeat every 15 min, no metrics) | "Pause monitoring" | - | - |
| Send error messages and tracebacks (default on) | "Send error messages" | - | - |
| Allow plain `http://` API URLs (testing only) | - | `fivenines_allow_insecure_http = True` | `FIVENINES_ALLOW_INSECURE_HTTP` |
| Keep counting requests with `log_level = warn` (default on) | - | `fivenines_capture_quiet_werkzeug` | `FIVENINES_CAPTURE_QUIET_WERKZEUG` |
| Spool directory (default `<tmp>/fivenines-<uid>`) | - | `fivenines_spool_dir` | `FIVENINES_SPOOL_DIR` |

The most specific value wins: Settings, then the config file, then the environment. A key in
the config file or the environment ships with your deployment and enrolls every database that has
the module installed (use "Pause monitoring" to exclude one). A server-wide key always goes to
the server-wide API URL (config file, environment or default), never to a URL set in one
database's Settings. Odoo 19 prints one "unknown option" warning per `fivenines_*` option at
startup: it is harmless, Odoo keeps the value.

## How it works

- A logging handler in every Odoo process counts the HTTP access lines (status code, SQL count,
  SQL time, other time: the `werkzeug` lines with Odoo's `perf_info` up to Odoo 19, the
  `odoo.http.server` lines of Odoo 20's own HTTP server) and the WARNING/ERROR/CRITICAL
  records, per database (`threading.current_thread().dbname`).
- Each process flushes its cumulative counters every 10 s to
  `<tmp>/fivenines-<uid>/<db>-<hash>/<pid>-<start>.json` (atomic rename).
- A scheduled action ("Fivenines: push metrics", every minute) sums the files, subtracts what
  Fivenines already acknowledged, adds crons, database and system gauges, and pushes. Files of
  dead processes are removed after their last counters were delivered. When Fivenines cannot be
  reached nothing is lost: the next push covers the longer window. Retries back off up to 15 min.
- The enrollment key is exchanged once for a per-instance secret, stored in
  `ir.config_parameter` (administrators only); a key pasted in Settings is then deleted. Every
  push also sends the URLs the database knows (`web.base.url` and the website domains), so
  Fivenines can match existing uptime monitors.
- A fingerprint of where the database runs (name, `database.uuid`, `web.base.url`, Odoo.sh
  stage, neutralized or not) is checked on every run. A copy (another name or uuid, another
  stage, a neutralized copy) announces itself to Fivenines with the secret it copied, and gets a
  new secret for a new database, proposed for approval: it never reports as the original. A
  `web.base.url` change alone (Odoo rewrites it on admin logins) is reported to Fivenines, which
  tells a second live copy apart.
- Odoo's neutralization (Odoo.sh staging, `odoo-bin neutralize`) is respected: it turns the
  push off and the module never turns it back on by itself. The copy's settings screen says
  "This database is a neutralized copy: monitoring is off", and one click on "Turn it on"
  starts it; the copy then announces itself as above.
- Waiting for approval, the module keeps its secret, sends nothing that would pile up and checks
  again every 15 minutes (or what Fivenines asks). "Ignored" in Fivenines is final: the module
  stops, and "Re-enroll" with a key proposes the database again.
- A refused secret (HTTP 401, e.g. revoked in Fivenines) stops the pushes; the module retries
  once a day and never re-enrolls on its own. "Re-enroll" in Settings (with a key) starts over.
- Secrets travel only in the `Authorization` header, over HTTPS, and are never logged.

## Odoo.sh notes

- Per the Odoo.sh FAQ (quoted in issue #1), scheduled actions on staging and development branches
  run only a few times a day, and Odoo's neutralization deactivates every scheduled action of a
  neutralized copy. Monitoring of staging/dev is best-effort. The production cadence and
  lateness under load are not verified on Odoo.sh yet.
- Each branch is its own database with its own fingerprint (`ODOO_STAGE` and the database name
  differ), so production and its copies never mix.

## Limitations

- Several Odoo servers behind a load balancer, sharing one database: each node keeps its own
  counters and stream (the spool directory is local), and the push runs on whichever node picks
  the scheduled action. Fivenines then sees pushes alternating between the nodes: request and
  error counters add up across them, system figures alternate between machines, and a change of
  `web.base.url` shows up as a database waiting for approval (contract section 5, "Limitation:
  multi-node Odoo").
- With `log_level = debug_sql` Odoo itself logs every SQL statement with its values, including
  the row that stores the secret. Do not run production at that level.
- Error messages and tracebacks are sent as logged (bounded: 2000 and 8000 characters) unless
  "Send error messages" is off. Credentials in them (passwords and tokens in URLs, DSNs,
  `Authorization` headers, `password=`/`api_key:` pairs, bearer tokens, JWTs, long hex keys) are
  masked by patterns, which cannot recognize a secret in every shape (free text, an unnamed
  value).

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

CI (`.github/workflows/ci.yml`) runs the tests on Odoo 16, 17, 18, 19 and 20 with the official Docker
images and PostgreSQL 16, and checks on each that the release zip installs and upgrades
(`tools/build_zip.sh`, `tools/check_release_zip.sh`). A manual `publish` job builds the
`16.0`-`20.0` branches for the Odoo Apps Store only (it indexes one branch per Odoo version; dry
run by default).

### Releasing

The manifest `version` is serie-free and in two parts, `x.y` (see the comment in
`__manifest__.py`): Odoo adds its own serie at load time (`17.0.1.0`), a serie-prefixed version
would be refused by the other series, and Odoo 16 never runs the migrations of a three-part
`x.y.z`. A release bumps `y` (migrations, if any, go in `fivenines_monitoring/migrations/x.y/`):

1. Set `'version': 'x.y'` in `fivenines_monitoring/__manifest__.py`, merge to `main`.
2. Tag and push: `git tag vx.y && git push origin vx.y`. The `Release` workflow
   (`.github/workflows/release.yml`) builds the zip, checks it on 16.0 to 20.0, and publishes the
   GitHub release marked latest, so the link above serves it at once.
3. Optionally, run the `publish` job for the Odoo Apps Store.

To check a zip locally: `tools/build_zip.sh HEAD dist`, then
`tools/check_release_zip.sh dist/fivenines_monitoring.zip <new database> <python> <odoo-bin>
--db_host=localhost --db_user=$USER --addons-path-prefix=<odoo>/addons`.

## License

LGPL-3. See `LICENSE`.
