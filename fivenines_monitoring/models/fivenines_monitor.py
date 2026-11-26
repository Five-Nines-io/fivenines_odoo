# Part of Fivenines Monitoring. License LGPL-3.
"""The minute push: enrollment, fingerprint, collectors, delivery.

Everything here runs inside Odoo: in the cron (one run per minute) or from the
settings buttons. It must never raise out of the cron (Odoo 18+ deactivates a
cron that keeps failing) and never block it (short HTTP timeouts, backoff).
"""

import hashlib
import json
import logging
import os
import platform
import socket
import threading
import time
from datetime import datetime
from urllib.parse import urlsplit

import odoo
from odoo import SUPERUSER_ID, api, fields, models, release, tools

from ..lib import client as fn_client
from ..lib import spool, stats
from ..lib import system as fn_system
from ..lib.collector import COLLECTOR

_logger = logging.getLogger(__name__)

MODULE = 'fivenines_monitoring'
SCHEMA_VERSION = 1

# ir.config_parameter keys (readable by administrators only)
P_KEY = 'fivenines.enrollment_key'
P_PAUSED = 'fivenines.paused'
P_API_URL = 'fivenines.api_url'
P_SECRET = 'fivenines.instance_secret'
P_INSTANCE = 'fivenines.instance_id'
P_FINGERPRINT = 'fivenines.fingerprint'
P_ENROLLED_AT = 'fivenines.enrolled_at'
P_STATUS = 'fivenines.status'
P_SERVER = 'fivenines.server_identity'
STATE_PARAMS = (P_SECRET, P_INSTANCE, P_FINGERPRINT, P_ENROLLED_AT, P_STATUS, P_SERVER)

LATE_THRESHOLD = 300    # a due cron not picked up for 5 min is late
STUCK_THRESHOLD = 1800  # a cron still running 30 min after its due time is stuck
MAX_CRON_ITEMS = 50
HOLD_LONG = 3600        # 402 / 403: try again in an hour
WARN_EVERY = 900        # rate limit of our own warnings, per kind

_last_warning = {}


def _warn(kind, message, *args, exc_info=False):
    """Log at most one warning of each kind per WARN_EVERY seconds."""
    now = time.time()
    if now - _last_warning.get(kind, 0) >= WARN_EVERY:
        _last_warning[kind] = now
        _logger.warning(message, *args, exc_info=exc_info)


def _conf(name, env_name):
    value = tools.config.get(name)
    if value not in (None, False, ''):
        return str(value).strip(), 'odoo.conf'
    value = os.environ.get(env_name)
    if value and value.strip():
        return value.strip(), 'environment'
    return None, None


def _conf_bool(name, env_name, default):
    value, _source = _conf(name, env_name)
    if value is None:
        return default
    return value.lower() in ('1', 'true', 'yes', 'on')


def _key_hash(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]


def normalize_url(url):
    """scheme://host[:port][/path] lowercased, default port and trailing / dropped."""
    if not url:
        return None
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.hostname:
        return url.strip().rstrip('/') or None
    host = parts.hostname.lower()
    port = parts.port
    if port and not ((parts.scheme == 'http' and port == 80) or (parts.scheme == 'https' and port == 443)):
        host = '%s:%d' % (host, port)
    return '%s://%s%s' % (parts.scheme.lower(), host, parts.path.rstrip('/'))


def _is_loopback_url(url):
    if not url:
        return True
    return fn_client.is_loopback(urlsplit(url).hostname)


def _testing():
    return bool(getattr(threading.current_thread(), 'testing', False)
                or getattr(odoo.modules.module, 'current_test', None))


def _epoch(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)
    return round((dt - datetime(1970, 1, 1)).total_seconds(), 3)


class FiveninesMonitor(models.AbstractModel):
    _name = 'fivenines.monitor'
    _description = 'Fivenines Monitoring'

    # ------------------------------------------------------------------
    # process setup
    # ------------------------------------------------------------------
    def _register_hook(self):
        super()._register_hook()
        try:
            COLLECTOR.register_db(self.env.cr.dbname, self._fn_spool_dir())
            COLLECTOR.install(force_werkzeug_info=_conf_bool(
                'fivenines_capture_quiet_werkzeug', 'FIVENINES_CAPTURE_QUIET_WERKZEUG', True))
        except Exception:  # noqa: BLE001
            _logger.warning('Fivenines: could not install the request collector', exc_info=True)

    @api.model
    def _fn_spool_dir(self):
        override, _src = _conf('fivenines_spool_dir', 'FIVENINES_SPOOL_DIR')
        return spool.db_dir(self.env.cr.dbname, tools.config.get('db_host'),
                            tools.config.get('db_port'), override)

    @api.model
    def _setup_cron(self):
        """Called from data/ir_cron.xml: Odoo 16/17 have numbercall (default 1
        = run once) and doall; 18+ removed both. Make the cron run forever."""
        cron = self.env.ref('%s.ir_cron_fivenines_push' % MODULE, raise_if_not_found=False)
        if not cron:
            return
        vals = {}
        if 'numbercall' in cron._fields:
            vals['numbercall'] = -1
        if 'doall' in cron._fields:
            vals['doall'] = False
        if vals:
            cron.sudo().write(vals)

    # ------------------------------------------------------------------
    # settings
    # ------------------------------------------------------------------
    @api.model
    def _fn_params(self):
        """Settings from this transaction, state from the committed database.

        Settings (key, pause, URL) may have just been written by this very
        transaction (the "Send now" button saves first). State parameters are
        only ever written on their own committed cursor (_fn_store), which a
        REPEATABLE READ transaction started earlier cannot see: read them on a
        fresh cursor too, or a second run in one transaction would enroll twice.
        """
        icp = self.env['ir.config_parameter'].sudo()
        params = {k: icp.get_param(k) or None for k in (P_KEY, P_PAUSED, P_API_URL)}
        registry = self.env.registry
        if _testing() or (hasattr(registry, 'in_test_mode') and registry.in_test_mode()):
            params.update({k: icp.get_param(k) or None for k in STATE_PARAMS})
            return params
        with registry.cursor() as cr:
            cr.execute('SELECT key, value FROM ir_config_parameter WHERE key IN %s', [STATE_PARAMS])
            found = dict(cr.fetchall())
        params.update({k: found.get(k) or None for k in STATE_PARAMS})
        return params

    @api.model
    def _fn_enrollment_key(self, params=None):
        params = params if params is not None else self._fn_params()
        key = (params.get(P_KEY) or '').strip()
        if key:
            return key, 'settings'
        return _conf('fivenines_enrollment_key', 'FIVENINES_ENROLLMENT_KEY')

    @api.model
    def _fn_api_url(self, params=None):
        params = params if params is not None else self._fn_params()
        url = (params.get(P_API_URL) or '').strip()
        if not url:
            url = _conf('fivenines_api_url', 'FIVENINES_API_URL')[0] or fn_client.DEFAULT_API_URL
        return fn_client.check_api_url(url, allow_insecure=_conf_bool(
            'fivenines_allow_insecure_http', 'FIVENINES_ALLOW_INSECURE_HTTP', False))

    @api.model
    def _fn_store(self, values):
        """Write parameters on their own committed cursor.

        The secret must survive even if the surrounding transaction rolls back
        (a serialization retry would otherwise enroll twice). In tests we stay
        on the test cursor.
        """
        values = {k: (v if v not in (None, '') else False) for k, v in values.items()}
        registry = self.env.registry
        if _testing() or (hasattr(registry, 'in_test_mode') and registry.in_test_mode()):
            icp = self.env['ir.config_parameter'].sudo()
            for k, v in values.items():
                icp.set_param(k, v)
            return
        with registry.cursor() as cr:
            icp = api.Environment(cr, SUPERUSER_ID, {})['ir.config_parameter']
            for k, v in values.items():
                icp.set_param(k, v)

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------
    @api.model
    def _fn_fingerprint(self):
        icp = self.env['ir.config_parameter'].sudo()
        components = {
            'database': self.env.cr.dbname,
            'database_uuid': icp.get_param('database.uuid') or None,
            'base_url': normalize_url(icp.get_param('web.base.url')),
            'odoo_stage': os.environ.get('ODOO_STAGE') or None,
        }
        digest = hashlib.sha256(json.dumps(components, sort_keys=True).encode()).hexdigest()
        return components, digest

    @api.model
    def _fn_server_identity(self):
        """Odoo master process (pid + start time) and server mode."""
        import psutil  # noqa: PLC0415
        from odoo.service import server as odoo_server  # noqa: PLC0415
        server = getattr(odoo_server, 'server', None)
        mode = {
            'PreforkServer': 'prefork',
            'ThreadedServer': 'threaded',
            'GeventServer': 'gevent',
        }.get(type(server).__name__) if server is not None else None
        pid = getattr(server, 'pid', None) or os.getpid()
        try:
            started_at = round(psutil.Process(pid).create_time(), 2)
        except Exception:  # noqa: BLE001
            pid, started_at = os.getpid(), round(COLLECTOR.started_at, 2)
        return {'pid': pid, 'started_at': started_at, 'mode': mode}

    @api.model
    def _fn_module_version(self):
        try:
            return odoo.modules.module.get_manifest(MODULE).get('version')
        except Exception:  # noqa: BLE001
            return None

    @api.model
    def _fn_user_agent(self):
        return 'fivenines-odoo/%s (Odoo %s; Python %s)' % (
            self._fn_module_version(), release.version, platform.python_version())

    @api.model
    def _fn_instance_info(self, components, digest):
        self.env.cr.execute(
            "SELECT 1 FROM ir_module_module WHERE name = 'web_enterprise' AND state = 'installed'")
        enterprise = bool(self.env.cr.fetchone())
        return {
            'fingerprint': digest,
            'fingerprint_components': components,
            'database': components['database'],
            'database_uuid': components['database_uuid'],
            'base_url': components['base_url'],
            'odoo_stage': components['odoo_stage'],
            'odoo_version': release.version,
            'odoo_serie': release.serie,
            'odoo_version_info': list(release.version_info),
            'edition': 'enterprise' if enterprise else 'community',
            'module_version': self._fn_module_version(),
            'python_version': platform.python_version(),
            'hostname': socket.gethostname(),
            'workers': tools.config.get('workers'),
            'max_cron_threads': tools.config.get('max_cron_threads'),
        }

    # ------------------------------------------------------------------
    # state file (frequent writes stay out of the database: every
    # ir.config_parameter write clears the ORM caches of every worker)
    # ------------------------------------------------------------------
    @api.model
    def _fn_load_state(self, directory):
        return spool.read_json(os.path.join(directory, spool.STATE_FILE)) or {}

    @api.model
    def _fn_save_state(self, directory, state):
        spool.write_json_atomic(os.path.join(directory, spool.STATE_FILE), state)

    @api.model
    def _fn_fresh_baseline(self, directory, now):
        """Current counters of every process become the acknowledged baseline."""
        COLLECTOR.flush(self.env.cr.dbname)
        acked = {}
        for key, path, _pid, _start in spool.list_process_files(directory):
            doc = spool.read_json(path)
            if doc and isinstance(doc.get('stats'), dict):
                acked[key] = doc['stats']
        return {'acked': acked, 'last_ack_end': now, 'seq': 0, 'baseline_reset': True}

    # ------------------------------------------------------------------
    # cron entry point
    # ------------------------------------------------------------------
    @api.model
    def _cron_push(self):
        try:
            self._fn_run(trigger='cron')
        except Exception:  # noqa: BLE001 - never fail the cron
            _warn('run', 'Fivenines: push failed', exc_info=True)

    @api.model
    def _fn_run(self, trigger='cron', force=False, reenroll=False):
        """One collection + push. Returns a small dict describing what happened."""
        directory = spool.ensure_dir(self._fn_spool_dir())
        with spool.StateLock(directory) as lock:
            if not lock.acquired:
                return {'result': 'busy'}
            state = self._fn_load_state(directory)
            try:
                outcome = self._fn_run_locked(directory, state, trigger, force, reenroll)
            except Exception as e:  # noqa: BLE001
                outcome = {'result': 'error', 'message': '%s: %s' % (type(e).__name__, str(e)[:200])}
                _warn('run', 'Fivenines: push failed', exc_info=True)
            state['last_run'] = dict(outcome, at=time.time(), trigger=trigger)
            self._fn_save_state(directory, state)
            return outcome

    @api.model
    def _fn_run_locked(self, directory, state, trigger, force, reenroll=False):
        now = time.time()
        params = self._fn_params()
        previous_instance = None
        if reenroll:
            # Administrator asked for a new enrollment: forget the secret (and a
            # revoked / refused status). Our own copy of the params is updated
            # too: this transaction cannot see the committed write.
            previous_instance = params.get(P_INSTANCE)
            self._fn_forget(keep_status=False)
            params = dict(params, **{k: None for k in STATE_PARAMS})
            state.clear()
        if (params.get(P_PAUSED) or '').lower() in ('true', '1'):
            self._fn_sweep(directory, state)
            return {'result': 'paused'}
        if not force and state.get('next_attempt_at', 0) > now:
            return {'result': 'backoff', 'next_attempt_at': state['next_attempt_at']}

        try:
            api_url = self._fn_api_url(params)
        except ValueError as e:
            return {'result': 'config_error', 'message': str(e)}
        api_client = fn_client.Client(api_url, self._fn_user_agent())

        components, digest = self._fn_fingerprint()
        secret = params.get(P_SECRET)
        enroll_reason = 'manual' if reenroll else 'first_enrollment'
        fingerprint_change = None
        stored = json.loads(params[P_FINGERPRINT]) if params.get(P_FINGERPRINT) else None
        if stored and stored.get('hash') != digest:
            old = stored.get('components') or {}
            changed = sorted(k for k in components if components.get(k) != old.get(k))
            if changed == ['base_url'] and _is_loopback_url(old.get('base_url')):
                # localhost -> real URL (first admin login updates web.base.url):
                # the same instance, not a copy. Adopt the new URL.
                fingerprint_change = 'base_url_from_loopback'
                self._fn_store({P_FINGERPRINT: json.dumps({'hash': digest, 'components': components})})
            else:
                _logger.info('Fivenines: instance location changed (%s), enrolling as a new instance',
                             ', '.join(changed))
                previous_instance = params.get(P_INSTANCE)
                enroll_reason = 'fingerprint_changed'
                secret = None
                self._fn_forget(keep_status=False)
                params = dict(params, **{k: None for k in STATE_PARAMS})
                state.clear()

        if not secret:
            status = json.loads(params[P_STATUS]) if params.get(P_STATUS) else {}
            if status.get('state') == 'revoked':
                # only "Re-enroll" (which clears this status) may resume
                return {'result': 'revoked'}
            outcome = self._fn_enroll(api_client, directory, state, params, components, digest,
                                      enroll_reason, previous_instance, force)
            if outcome.get('result') != 'enrolled':
                return outcome
            secret = outcome.pop('secret')
            params = dict(params, **{P_INSTANCE: outcome['instance_id'], P_SERVER: None})

        if not state.get('acked') and 'last_ack_end' not in state:
            state.update(self._fn_fresh_baseline(directory, now))

        payload, commit = self._fn_build_payload(directory, state, params, components, digest, now)
        payload['instance']['fingerprint_change'] = fingerprint_change
        result = api_client.push(secret, payload)
        return self._fn_handle_push(api_client, directory, state, params, components, digest,
                                    payload, commit, result, now, trigger)

    # ------------------------------------------------------------------
    # enrollment
    # ------------------------------------------------------------------
    @api.model
    def _fn_forget(self, keep_status=True):
        values = {k: False for k in STATE_PARAMS if not (keep_status and k == P_STATUS)}
        self._fn_store(values)

    @api.model
    def _fn_enroll(self, api_client, directory, state, params, components, digest, reason,
                   previous_instance, force):
        key, source = self._fn_enrollment_key(params)
        if not key:
            return {'result': 'no_key'}
        status = json.loads(params[P_STATUS]) if params.get(P_STATUS) else {}
        if (status.get('state') == 'enrollment_refused' and status.get('key_hash') == _key_hash(key)
                and not force):
            return {'result': 'enrollment_refused'}
        body = {
            'schema_version': SCHEMA_VERSION,
            'reason': reason,
            'previous_instance_id': previous_instance,
            'key_source': source,
            'instance': self._fn_instance_info(components, digest),
        }
        result = api_client.enroll(key, body)
        now = time.time()
        if result.ok:
            data = result.data
            self._fn_store({
                P_SECRET: data['token'],
                P_INSTANCE: str(data['instance_id']),
                P_FINGERPRINT: json.dumps({'hash': digest, 'components': components}),
                P_ENROLLED_AT: str(int(now)),
                P_STATUS: False,
                P_SERVER: False,
            })
            state.clear()
            state.update(self._fn_fresh_baseline(directory, now))
            _logger.info('Fivenines: enrolled as instance %s', data['instance_id'])
            return {'result': 'enrolled', 'instance_id': str(data['instance_id']), 'secret': data['token']}
        if result.kind == fn_client.UNAUTHORIZED:
            self._fn_store({P_STATUS: json.dumps({
                'state': 'enrollment_refused', 'key_hash': _key_hash(key), 'at': int(now),
                'message': result.message})})
            _warn('enroll401', 'Fivenines: the enrollment key was refused (HTTP 401). '
                  'Paste a valid key to retry.')
            return {'result': 'enrollment_refused', 'status': result.status, 'message': result.message}
        self._fn_schedule_retry(state, result, now)
        _warn('enroll', 'Fivenines: enrollment failed (%s %s), will retry', result.status or '-',
              result.message or result.kind)
        return {'result': 'enroll_failed', 'kind': result.kind, 'status': result.status,
                'message': result.message}

    @api.model
    def _fn_schedule_retry(self, state, result, now):
        if result.kind in (fn_client.PAYMENT_REQUIRED, fn_client.FORBIDDEN):
            delay = HOLD_LONG
        elif result.kind == fn_client.RATE_LIMITED:
            delay = result.retry_after or 60
        else:
            state['failures'] = state.get('failures', 0) + 1
            delay = result.retry_after or fn_client.backoff_delay(state['failures'])
        # the cron fires every minute; land just before the run we want
        state['next_attempt_at'] = now + delay - 5
        state['last_error'] = {'at': now, 'kind': result.kind, 'status': result.status,
                               'message': result.message}

    # ------------------------------------------------------------------
    # push
    # ------------------------------------------------------------------
    @api.model
    def _fn_handle_push(self, api_client, directory, state, params, components, digest,
                        payload, commit, result, now, trigger):
        base = {'status': result.status, 'seq': payload['seq']}
        if result.ok:
            state['acked'] = commit['acked']
            state['acked_workers'] = commit['workers']
            state['last_ack_end'] = now
            state['seq'] = payload['seq']
            state['failures'] = 0
            state['baseline_reset'] = False
            state['system_prev'] = commit['system_prev']
            state.pop('next_attempt_at', None)
            state['last_success'] = {'at': now, 'summary': commit['summary']}
            for path in commit['delete']:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            server = commit['server']
            if server and params.get(P_SERVER) != json.dumps(server, sort_keys=True):
                self._fn_store({P_SERVER: json.dumps(server, sort_keys=True)})
            return dict(base, result='pushed', **commit['summary'])
        if result.kind == fn_client.UNAUTHORIZED:
            # Revoked in Fivenines: stop. Re-enrolling on our own would undo the
            # revocation, so only an administrator ("Re-enroll") can resume.
            self._fn_store({P_SECRET: False, P_STATUS: json.dumps({
                'state': 'revoked', 'at': int(now), 'message': result.message})})
            _warn('push401', 'Fivenines: the instance secret was revoked (HTTP 401); pushes stopped. '
                  'Use "Re-enroll" in the Fivenines settings to resume.')
            return dict(base, result='revoked', message=result.message)
        if result.kind == fn_client.CONFLICT and trigger != 'conflict':
            # The same secret is used from another place: we are a copy.
            _logger.info('Fivenines: fingerprint conflict (HTTP 409), enrolling as a new instance')
            previous = params.get(P_INSTANCE)
            self._fn_forget(keep_status=False)
            state.clear()
            fresh = dict(params, **{k: None for k in STATE_PARAMS})
            outcome = self._fn_enroll(api_client, directory, state, fresh, components, digest,
                                      'conflict', previous, True)
            return dict(base, result='conflict', enroll=outcome.get('result'),
                        instance_id=outcome.get('instance_id'))
        self._fn_schedule_retry(state, result, now)
        if result.kind == fn_client.REJECTED:
            _warn('rejected', 'Fivenines: push rejected (HTTP %s): %s', result.status, result.message)
        else:
            _warn('push', 'Fivenines: push failed (%s %s), will retry', result.status or '-',
                  result.message or result.kind)
        return dict(base, result='push_failed', kind=result.kind, message=result.message,
                    next_attempt_at=state.get('next_attempt_at'))

    @api.model
    def _fn_sweep(self, directory, state):
        """Delete files of dead processes (used while paused / not enrolled)."""
        now = time.time()
        acked = state.get('acked') or {}
        for key, path, pid, start in spool.list_process_files(directory):
            doc = spool.read_json(path) or {}
            stale = now - doc.get('flushed_at', 0) > spool.STALE_AFTER
            if stale or not spool.process_alive(pid, doc.get('started_at', start)):
                try:
                    os.unlink(path)
                except OSError:
                    pass
                acked.pop(key, None)

    @api.model
    def _fn_build_payload(self, directory, state, params, components, digest, now):
        errors = []

        def guard(name, fn):
            try:
                return fn()
            except Exception as e:  # noqa: BLE001
                errors.append({'collector': name, 'type': type(e).__name__, 'message': str(e)[:200]})
                return None

        # -- per-process counters -> deltas since the last acknowledged push
        COLLECTOR.flush(self.env.cr.dbname)
        acked = state.get('acked') or {}
        agg = stats.empty_stats()
        new_acked, delete, workers = {}, [], []
        for key, path, pid, start in spool.list_process_files(directory):
            doc = spool.read_json(path)
            if not doc or not isinstance(doc.get('stats'), dict):
                continue
            current = doc['stats']
            part = stats.delta(current, acked.get(key))
            if part is None:
                part = stats.delta(current, None)
            stats.merge_into(agg, part)
            started_at = doc.get('started_at', start)
            alive = spool.process_alive(pid, started_at)
            if alive and now - doc.get('flushed_at', 0) <= spool.STALE_AFTER:
                new_acked[key] = current
                workers.append({'pid': pid, 'started_at': round(started_at, 2),
                                'last_flush_at': round(doc.get('flushed_at', 0), 3)})
            else:
                delete.append(path)

        start = state.get('last_ack_end') or now
        window_seconds = max(0.0, now - start)
        server = guard('process', self._fn_server_identity)

        # -- restart / worker-set events (against the last ACKNOWLEDGED view,
        #    so an event is resent until Fivenines got it)
        events = []
        previous_server = json.loads(params[P_SERVER]) if params.get(P_SERVER) else None
        if server and previous_server and (
                previous_server.get('pid') != server['pid']
                or int(previous_server.get('started_at') or 0) != int(server['started_at'])):
            events.append({'type': 'server_restart', 'at': server['started_at'],
                           'previous': previous_server, 'current': server})
        current_keys = sorted('%d-%d' % (w['pid'], int(w['started_at'])) for w in workers)
        previous_keys = state.get('acked_workers')
        if previous_keys is not None and set(previous_keys) != set(current_keys):
            started = sorted(set(current_keys) - set(previous_keys))
            exited = sorted(set(previous_keys) - set(current_keys))
            events.append({'type': 'workers_changed', 'at': now,
                           'started': [int(k.split('-')[0]) for k in started],
                           'exited': [int(k.split('-')[0]) for k in exited]})

        system_block, system_prev = None, state.get('system_prev')
        if server:
            filestore = tools.config.filestore(self.env.cr.dbname)
            data_path = filestore if os.path.isdir(filestore) else tools.config.get('data_dir')
            res = guard('system', lambda: fn_system.collect(
                state.get('system_prev'), data_path, server['pid'], now=now))
            if res:
                system_block, system_prev, sys_errors = res
                errors.extend(sys_errors)

        http_block = stats.http_payload(agg, window_seconds, COLLECTOR.werkzeug_capture != 'disabled')
        payload = {
            'schema_version': SCHEMA_VERSION,
            'sent_at': round(now, 3),
            'seq': (state.get('seq') or 0) + 1,
            'window': {
                'start': round(start, 3),
                'end': round(now, 3),
                'seconds': round(window_seconds, 3),
                'baseline_reset': bool(state.get('baseline_reset')),
            },
            'instance': dict(self._fn_instance_info(components, digest),
                             instance_id=params.get(P_INSTANCE)),
            'process': dict(server or {}, workers=workers,
                            request_capture=COLLECTOR.werkzeug_capture) if server else None,
            'events': events,
            'http': http_block,
            'logs': stats.logs_payload(agg),
            'crons': guard('crons', self._fn_collect_crons),
            'database': guard('database', self._fn_collect_database),
            'system': system_block,
            'collector_errors': errors,
        }
        commit = {
            'acked': new_acked,
            'workers': current_keys,
            'delete': delete,
            'server': server,
            'system_prev': system_prev,
            'summary': {
                'requests': http_block['requests_total'] if http_block else None,
                'errors': payload['logs']['error_count'] + payload['logs']['critical_count'],
                'workers': len(workers),
            },
        }
        return payload, commit

    # ------------------------------------------------------------------
    # collectors that use Odoo's own cursor
    # ------------------------------------------------------------------
    @api.model
    def _fn_collect_crons(self):
        Cron = self.env['ir.cron'].sudo().with_context(active_test=True, lang='en_US')
        has_failures = 'failure_count' in Cron._fields
        fields_ = ['cron_name', 'nextcall', 'lastcall', 'interval_number', 'interval_type', 'priority']
        if has_failures:
            fields_ += ['failure_count', 'first_failure_date']
        rows = Cron.search_read([('active', '=', True)], fields_, order='nextcall')
        own = self.env.ref('%s.ir_cron_fivenines_push' % MODULE, raise_if_not_found=False)
        own_id = own.id if own else None
        now = fields.Datetime.now()
        due = [r for r in rows if r['nextcall'] and r['nextcall'] <= now and r['id'] != own_id]
        running = self._fn_locked_crons([r['id'] for r in due])
        jobs = []
        counts = {'late': 0, 'stuck': 0, 'running': 0, 'overdue': 0}
        for r in rows:
            if r['id'] == own_id:
                continue
            lateness = (now - r['nextcall']).total_seconds() if r['nextcall'] else 0
            is_running = None if running is None else r['id'] in running
            failing = bool(has_failures and r.get('failure_count'))
            state = None
            if lateness > LATE_THRESHOLD:
                counts['overdue'] += 1
                if is_running is True:
                    state = 'stuck' if lateness > STUCK_THRESHOLD else 'running'
                elif is_running is False:
                    state = 'late'
            elif is_running:
                state = 'running'
            if state:
                counts[state] += 1
            if state or failing:
                jobs.append({
                    'id': r['id'],
                    'name': (r['cron_name'] or '')[:200],
                    'state': state or 'failing',
                    'nextcall': _epoch(r['nextcall']),
                    'lastcall': _epoch(r['lastcall']),
                    'lateness_seconds': round(max(0.0, lateness), 1),
                    'interval': '%s %s' % (r['interval_number'], r['interval_type']),
                    'priority': r['priority'],
                    'running': is_running,
                    'failure_count': r.get('failure_count') if has_failures else None,
                    'first_failure_at': _epoch(r.get('first_failure_date')) if has_failures else None,
                })
        order = {'stuck': 0, 'late': 1, 'failing': 2, 'running': 3}
        jobs.sort(key=lambda j: (order.get(j['state'], 9), -j['lateness_seconds']))
        probe_ok = running is not None
        return {
            'active_count': len(rows) - (1 if own_id and any(r['id'] == own_id for r in rows) else 0),
            'due_count': len(due),
            'overdue_count': counts['overdue'],
            'running_count': counts['running'] + counts['stuck'] if probe_ok else None,
            'late_count': counts['late'] if probe_ok else None,
            'stuck_count': counts['stuck'] if probe_ok else None,
            'failing_count': sum(1 for r in rows if r.get('failure_count')) if has_failures else None,
            'failure_fields_available': has_failures,
            'late_threshold_seconds': LATE_THRESHOLD,
            'stuck_threshold_seconds': STUCK_THRESHOLD,
            'jobs': jobs[:MAX_CRON_ITEMS],
            'jobs_truncated': len(jobs) > MAX_CRON_ITEMS,
        }

    @api.model
    def _fn_locked_crons(self, ids):
        """Ids among `ids` whose ir_cron row is locked right now = running.

        Odoo's cron runner holds `FOR NO KEY UPDATE` on the job row while the
        job runs. We probe with SKIP LOCKED (never waits) on a fresh cursor and
        roll back at once. None when the probe itself failed (unknown).
        """
        if not ids:
            return set()
        try:
            if _testing():
                cr = self.env.cr
                with cr.savepoint():
                    cr.execute('SELECT id FROM ir_cron WHERE id IN %s FOR NO KEY UPDATE SKIP LOCKED',
                               [tuple(ids)])
                    free = {row[0] for row in cr.fetchall()}
                    raise _Rollback()
            with self.env.registry.cursor() as cr:
                cr.execute('SELECT id FROM ir_cron WHERE id IN %s FOR NO KEY UPDATE SKIP LOCKED',
                           [tuple(ids)])
                free = {row[0] for row in cr.fetchall()}
                cr.rollback()
            return set(ids) - free
        except _Rollback:
            return set(ids) - free
        except Exception:  # noqa: BLE001
            return None

    @api.model
    def _fn_collect_database(self):
        cr = self.env.cr
        cr.execute('SELECT pg_database_size(current_database())')
        size = cr.fetchone()[0]
        cr.execute("""
            SELECT count(*),
                   count(*) FILTER (WHERE state = 'active'),
                   count(*) FILTER (WHERE state = 'idle'),
                   count(*) FILTER (WHERE state IN ('idle in transaction', 'idle in transaction (aborted)')),
                   count(*) FILTER (WHERE wait_event_type = 'Lock'),
                   EXTRACT(EPOCH FROM max(now() - xact_start)
                           FILTER (WHERE state <> 'idle' AND pid <> pg_backend_pid()))
              FROM pg_stat_activity
             WHERE datname = current_database()
        """)
        total, active, idle, idle_tx, waiting, longest = cr.fetchone()
        cr.execute("SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'")
        server_total = cr.fetchone()[0]
        cr.execute('SHOW max_connections')
        max_conn = int(cr.fetchone()[0])
        cr.execute('SHOW server_version_num')
        version_num = int(cr.fetchone()[0])
        return {
            'size_bytes': size,
            'connections': {
                'total': total,
                'active': active,
                'idle': idle,
                'idle_in_transaction': idle_tx,
                'waiting_on_lock': waiting,
            },
            'longest_transaction_seconds': round(float(longest), 3) if longest is not None else None,
            'server_connections_total': server_total,
            'server_max_connections': max_conn,
            'odoo_db_maxconn': tools.config.get('db_maxconn'),
            'postgresql_version_num': version_num,
        }

    # ------------------------------------------------------------------
    # status for the settings screen
    # ------------------------------------------------------------------
    @api.model
    def _fn_status(self):
        params = self._fn_params()
        key, source = self._fn_enrollment_key(params)
        try:
            state = self._fn_load_state(self._fn_spool_dir())
        except Exception:  # noqa: BLE001
            state = {}
        status = json.loads(params[P_STATUS]) if params.get(P_STATUS) else {}
        return {
            'key_source': source,
            'enrolled': bool(params.get(P_SECRET)),
            'instance_id': params.get(P_INSTANCE),
            'status': status.get('state'),
            'paused': (params.get(P_PAUSED) or '').lower() in ('true', '1'),
            'last_run': state.get('last_run'),
            'last_success': state.get('last_success'),
            'last_error': state.get('last_error'),
            'failures': state.get('failures', 0),
            'next_attempt_at': state.get('next_attempt_at'),
            'request_capture': COLLECTOR.werkzeug_capture,
        }


class _Rollback(Exception):
    pass
