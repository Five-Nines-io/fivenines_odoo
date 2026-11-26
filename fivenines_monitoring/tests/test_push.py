# Part of Fivenines Monitoring. License LGPL-3.
"""Enrollment, push and error handling against the stub server."""

import json
import logging
import os
import secrets
import shutil
import tempfile
import time
from datetime import timedelta
from unittest.mock import patch

import requests

from odoo import fields
from odoo.exceptions import AccessError
from odoo.tests.common import HttpCase, TransactionCase, tagged

from ..lib import collector as fn_collector
from ..lib import spool, stats
from ..lib.collector import COLLECTOR
from ..models import fivenines_monitor as fm
from .stub_server import StubServer, load_schema, validate


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        # odoo.sql_db at DEBUG (log_level = debug_sql) prints every SQL
        # statement with its values, whatever the module does: out of scope.
        if record.name == 'odoo.sql_db':
            return
        try:
            self.lines.append(record.getMessage())
        except Exception:  # noqa: BLE001
            self.lines.append(str(record.msg))
        if record.exc_info:
            self.lines.append(logging.Formatter().formatException(record.exc_info))


class FiveninesCase:
    """Shared setup: a stub server, a temp spool dir, a clean parameter set."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = secrets.token_hex(32)
        cls.stub = StubServer([cls.key]).start()

    @classmethod
    def tearDownClass(cls):
        cls.stub.stop()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.spool_dir = os.path.join(self.tmp, 'spool', 'db')
        Monitor = self.registry['fivenines.monitor']
        patcher = patch.object(Monitor, '_fn_spool_dir', lambda self_: self.spool_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        dbname = self.env.cr.dbname
        old = COLLECTOR.dbs.get(dbname)
        COLLECTOR.dbs[dbname] = self.spool_dir
        self.addCleanup(lambda: COLLECTOR.dbs.__setitem__(dbname, old) if old else COLLECTOR.dbs.pop(dbname, None))
        self.icp = self.env['ir.config_parameter'].sudo()
        for k in fm.STATE_PARAMS + (fm.P_KEY, fm.P_PAUSED, fm.P_API_URL):
            self.icp.set_param(k, False)
        self.icp.set_param(fm.P_API_URL, self.stub.url)
        self.icp.set_param(fm.P_KEY, self.key)
        self.icp.set_param('web.base.url', 'https://erp.example.com')
        with self.stub.state.lock:
            self.stub.state.enrollment_keys = {self.key: {'revoked': False}}
        requests.post(self.stub.url + '/_stub/reset', timeout=5)
        self.monitor = self.env['fivenines.monitor']

    # helpers
    def run_push(self, **kw):
        return self.monitor._fn_run(**kw)

    def stub_requests(self, path=None):
        return [r for r in self.stub.state.requests if path is None or r['path'] == path]

    def last_payload(self):
        return self.stub.state.pushes[-1]['payload']

    def fail_next(self, status, count=1, path='collect', retry_after=None):
        requests.post(self.stub.url + '/_stub/fail', json={
            'status': status, 'count': count, 'path': path, 'retry_after': retry_after}, timeout=5)

    def state_file(self):
        return spool.read_json(os.path.join(self.spool_dir, spool.STATE_FILE)) or {}

    def expire_backoff(self):
        state = self.state_file()
        state['next_attempt_at'] = 0
        spool.write_json_atomic(os.path.join(self.spool_dir, spool.STATE_FILE), state)

    def fake_process_file(self, pid, started_at, requests_2xx=0, errors=0):
        s = stats.empty_stats()
        for _i in range(requests_2xx):
            stats.record_request(s, 200, 40.0, 5, 2.0)
        for _i in range(errors):
            stats.record_log(s, 'ERROR', 'deadbeef', {
                'logger': 'odoo.x', 'level': 'ERROR', 'message_template': 'boom',
                'exception_type': None, 'exception_origin': None, 'location': 'x.py:1'})
        spool.ensure_dir(self.spool_dir)
        path = os.path.join(self.spool_dir, spool.proc_filename(pid, started_at))
        spool.write_json_atomic(path, {'pid': pid, 'ppid': 1, 'started_at': started_at,
                                       'flushed_at': time.time(), 'stats': s})
        return path


@tagged('post_install', '-at_install', 'fivenines')
class TestEnrollAndPush(FiveninesCase, TransactionCase):

    def test_enroll_then_push_valid_payload(self):
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        self.assertEqual([r['status'] for r in self.stub.state.requests], [201, 200])
        self.assertTrue(self.icp.get_param(fm.P_SECRET))
        instance_id = self.icp.get_param(fm.P_INSTANCE)
        self.assertTrue(instance_id.startswith('odi_'))
        payload = self.last_payload()
        self.assertEqual(validate(payload, load_schema('push_payload.schema.json')), [])
        self.assertEqual(self.stub.state.schema_errors, [])
        self.assertEqual(payload['instance']['instance_id'], instance_id)
        self.assertEqual(payload['instance']['database'], self.env.cr.dbname)
        self.assertEqual(payload['instance']['base_url'], 'https://erp.example.com')
        self.assertEqual(payload['seq'], 1)
        self.assertTrue(payload['window']['baseline_reset'])
        self.assertIsNotNone(payload['database']['size_bytes'])
        self.assertIsNotNone(payload['crons'])
        # second push: next seq, window starts where the first ended
        out2 = self.run_push()
        self.assertEqual(out2['result'], 'pushed')
        p2 = self.last_payload()
        self.assertEqual(p2['seq'], 2)
        self.assertEqual(p2['window']['start'], payload['window']['end'])
        self.assertFalse(p2['window']['baseline_reset'])
        self.assertEqual(len(self.stub_requests('enroll')), 1)

    def test_enroll_request_shape(self):
        self.run_push()
        inst = self.stub.state.instances
        self.assertEqual(len(inst), 1)
        record = list(inst.values())[0]
        self.assertEqual(record['reason'], 'first_enrollment')
        self.assertIsNone(record['previous_instance_id'])
        comps = record['fingerprint_components']
        self.assertEqual(set(comps), {'database', 'database_uuid', 'base_url', 'odoo_stage'})

    def test_no_key_no_request(self):
        self.icp.set_param(fm.P_KEY, False)
        with patch.dict(os.environ, {'FIVENINES_ENROLLMENT_KEY': ''}):
            out = self.run_push()
        self.assertEqual(out['result'], 'no_key')
        self.assertEqual(self.stub.state.requests, [])

    def test_key_from_environment(self):
        self.icp.set_param(fm.P_KEY, False)
        with patch.dict(os.environ, {'FIVENINES_ENROLLMENT_KEY': self.key}), \
                patch.object(fm, '_conf', side_effect=lambda name, env: (
                    (os.environ.get(env), 'environment') if os.environ.get(env) else (None, None))):
            self.assertEqual(self.monitor._fn_enrollment_key({fm.P_KEY: None}), (self.key, 'environment'))
            out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        # the settings value, when present, wins over the deployment config
        self.assertEqual(self.monitor._fn_enrollment_key({fm.P_KEY: 'abc'}), ('abc', 'settings'))

    def test_paused(self):
        self.icp.set_param(fm.P_PAUSED, True)
        self.assertEqual(self.run_push()['result'], 'paused')
        self.assertEqual(self.stub.state.requests, [])

    def test_secret_never_logged_nor_sent_in_body(self):
        capture = _LogCapture()
        root = logging.getLogger()
        root.addHandler(capture)
        old_level = root.level
        root.setLevel(logging.DEBUG)
        try:
            self.run_push()
            secret = self.icp.get_param(fm.P_SECRET)
            self.fail_next(503)
            self.run_push(force=True)
            requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                          json={'instance_id': self.icp.get_param(fm.P_INSTANCE)})
            self.run_push(force=True)
        finally:
            root.removeHandler(capture)
            root.setLevel(old_level)
        text = '\n'.join(capture.lines)
        self.assertTrue(secret)
        self.assertNotIn(secret, text)
        self.assertNotIn(self.key, text)
        for push in self.stub.state.pushes:
            body = json.dumps(push['payload'])
            self.assertNotIn(secret, body)
            self.assertNotIn(self.key, body)

    def test_cron_never_raises(self):
        with patch.object(self.registry['fivenines.monitor'], '_fn_run', side_effect=RuntimeError('x')):
            self.monitor._cron_push()  # must not raise

    def test_https_required(self):
        self.icp.set_param(fm.P_API_URL, 'http://api.fivenines.io')
        out = self.run_push()
        self.assertEqual(out['result'], 'config_error')
        self.assertEqual(self.stub.state.requests, [])


@tagged('post_install', '-at_install', 'fivenines')
class TestErrors(FiveninesCase, TransactionCase):

    def test_401_on_push_stops_until_reenroll(self):
        self.run_push()
        first = self.icp.get_param(fm.P_INSTANCE)
        requests.post(self.stub.url + '/_stub/revoke', json={'instance_id': first}, timeout=5)
        out = self.run_push()
        self.assertEqual(out['result'], 'revoked')
        self.assertFalse(self.icp.get_param(fm.P_SECRET))
        n = len(self.stub.state.requests)
        # the cron does not re-enroll on its own, even when forced ("Send now")
        self.assertEqual(self.run_push()['result'], 'revoked')
        self.assertEqual(self.run_push(force=True)['result'], 'revoked')
        self.assertEqual(len(self.stub.state.requests), n)
        # an administrator re-enrolls explicitly
        out = self.run_push(trigger='manual', force=True, reenroll=True)
        self.assertEqual(out['result'], 'pushed', out)
        second = self.icp.get_param(fm.P_INSTANCE)
        self.assertNotEqual(first, second)
        record = self.stub.state.instances[second]
        self.assertEqual(record['reason'], 'manual')
        self.assertEqual(record['previous_instance_id'], first)

    def test_401_on_enroll_waits_for_a_new_key(self):
        self.icp.set_param(fm.P_KEY, 'f' * 64)
        out = self.run_push()
        self.assertEqual(out['result'], 'enrollment_refused')
        n = len(self.stub.state.requests)
        self.assertEqual(self.run_push()['result'], 'enrollment_refused')
        self.assertEqual(len(self.stub.state.requests), n)  # no retry with the same key
        self.icp.set_param(fm.P_KEY, self.key)
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_409_reenrolls_as_new_instance(self):
        self.run_push()
        first = self.icp.get_param(fm.P_INSTANCE)
        self.fail_next(409)
        out = self.run_push()
        self.assertEqual(out['result'], 'conflict')
        self.assertEqual(out['enroll'], 'enrolled')
        second = self.icp.get_param(fm.P_INSTANCE)
        self.assertNotEqual(first, second)
        self.assertEqual(self.stub.state.instances[second]['reason'], 'conflict')
        self.assertEqual(self.stub.state.instances[second]['previous_instance_id'], first)
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_5xx_backoff_and_nothing_lost(self):
        self.run_push()
        pid, started = 4194000, 1000.0  # a dead process with unpushed counters
        path = self.fake_process_file(pid, started, requests_2xx=7, errors=2)
        self.fail_next(503, count=4)
        results = []
        for _i in range(4):
            results.append(self.run_push())
            self.expire_backoff()
        self.assertEqual({r['result'] for r in results}, {'push_failed'})
        self.assertTrue(os.path.exists(path), 'kept until a push succeeds')
        self.assertEqual(self.state_file()['failures'], 4)
        # after 4 failures the next attempt is 2 minutes away: skipped
        self.fail_next(503, count=1)
        self.run_push()
        self.assertEqual(self.run_push()['result'], 'backoff')
        self.expire_backoff()
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        payload = self.last_payload()
        self.assertEqual(payload['http']['requests_by_status']['2xx'], 7)
        self.assertEqual(payload['logs']['error_count'], 2)
        self.assertEqual(payload['seq'], 2, 'a failed push does not consume a seq')
        self.assertFalse(os.path.exists(path), 'dead process file removed after the push')
        self.assertEqual(self.state_file()['failures'], 0)
        out = self.run_push()
        self.assertEqual(self.last_payload()['http']['requests_by_status']['2xx'], 0, 'counted once')

    def test_timeout_is_retryable(self):
        self.run_push()
        with patch.object(requests, 'post', side_effect=requests.exceptions.ReadTimeout('slow')):
            out = self.run_push()
        self.assertEqual(out['result'], 'push_failed')
        self.assertEqual(out['kind'], 'retry')
        self.assertTrue(self.state_file()['next_attempt_at'] > time.time())

    def test_429_and_402_hold(self):
        self.run_push()
        self.fail_next(429, retry_after=120)
        self.run_push()
        self.assertGreater(self.state_file()['next_attempt_at'], time.time() + 100)
        self.expire_backoff()
        self.fail_next(402)
        self.run_push()
        self.assertGreater(self.state_file()['next_attempt_at'], time.time() + 3000)

    def test_422_is_backed_off_not_fatal(self):
        self.run_push()
        self.fail_next(422)
        out = self.run_push()
        self.assertEqual(out['kind'], 'rejected')
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_concurrent_run_is_skipped(self):
        spool.ensure_dir(self.spool_dir)
        with spool.StateLock(self.spool_dir) as lock:
            self.assertTrue(lock.acquired)
            self.assertEqual(self.run_push()['result'], 'busy')


@tagged('post_install', '-at_install', 'fivenines')
class TestFingerprint(FiveninesCase, TransactionCase):

    def test_copied_database_reenrolls(self):
        self.run_push()
        first = self.icp.get_param(fm.P_INSTANCE)
        # a copy made by Odoo's duplicate/restore-as-copy gets a new uuid
        self.icp.set_param('database.uuid', 'copied-%s' % secrets.token_hex(4))
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        second = self.icp.get_param(fm.P_INSTANCE)
        self.assertNotEqual(first, second)
        record = self.stub.state.instances[second]
        self.assertEqual(record['reason'], 'fingerprint_changed')
        self.assertEqual(record['previous_instance_id'], first)

    def test_new_public_url_reenrolls(self):
        self.run_push()
        first = self.icp.get_param(fm.P_INSTANCE)
        self.icp.set_param('web.base.url', 'https://staging.example.com')
        self.run_push()
        self.assertNotEqual(first, self.icp.get_param(fm.P_INSTANCE))

    def test_url_change_from_localhost_is_adopted(self):
        self.icp.set_param('web.base.url', 'http://localhost:8069')
        self.run_push()
        first = self.icp.get_param(fm.P_INSTANCE)
        self.icp.set_param('web.base.url', 'https://ERP.example.com:443/')
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        self.assertEqual(first, self.icp.get_param(fm.P_INSTANCE))
        payload = self.last_payload()
        self.assertEqual(payload['instance']['fingerprint_change'], 'base_url_from_loopback')
        self.assertEqual(payload['instance']['base_url'], 'https://erp.example.com')
        self.assertEqual(len(self.stub_requests('enroll')), 1)

    def test_copy_of_revoked_instance_can_enroll(self):
        self.run_push()
        requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                      json={'instance_id': self.icp.get_param(fm.P_INSTANCE)})
        self.assertEqual(self.run_push()['result'], 'revoked')
        self.icp.set_param('database.uuid', 'copy-of-revoked')
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_normalize_url(self):
        self.assertEqual(fm.normalize_url('HTTPS://Erp.Example.com:443/'), 'https://erp.example.com')
        self.assertEqual(fm.normalize_url('http://h:8069/odoo/'), 'http://h:8069/odoo')
        self.assertIsNone(fm.normalize_url(''))


@tagged('post_install', '-at_install', 'fivenines')
class TestEvents(FiveninesCase, TransactionCase):

    def test_restart_event(self):
        self.run_push()
        self.icp.set_param(fm.P_SERVER, json.dumps({'pid': 1, 'started_at': 1000.0, 'mode': 'prefork'}))
        self.run_push()
        events = self.last_payload()['events']
        self.assertEqual([e['type'] for e in events], ['server_restart'])
        self.assertEqual(events[0]['previous']['pid'], 1)
        stored = json.loads(self.icp.get_param(fm.P_SERVER))
        self.assertNotEqual(stored['pid'], 1)
        self.run_push()
        self.assertEqual(self.last_payload()['events'], [])

    def test_workers_changed_event(self):
        import psutil
        self.run_push()
        # any live process that is not this one (whose own file the collector writes)
        parent = psutil.Process(os.getppid())
        before = len(self.last_payload()['process']['workers'])
        self.fake_process_file(parent.pid, parent.create_time(), requests_2xx=1)
        self.run_push()
        events = self.last_payload()['events']
        self.assertEqual([e['type'] for e in events], ['workers_changed'], events)
        self.assertEqual(events[0]['started'], [parent.pid])
        self.assertEqual(len(self.last_payload()['process']['workers']), before + 1)


@tagged('post_install', '-at_install', 'fivenines')
class TestCrons(FiveninesCase, TransactionCase):

    def test_late_and_failing_crons(self):
        Cron = self.env['ir.cron'].sudo()
        late = Cron.search([('active', '=', True)], limit=1)
        if not late:
            self.skipTest('no active cron')
        vals = {'nextcall': fields.Datetime.now() - timedelta(minutes=20)}
        if 'failure_count' in Cron._fields:
            vals.update(failure_count=3, first_failure_date=fields.Datetime.now() - timedelta(days=1))
        late.write(vals)
        block = self.monitor._fn_collect_crons()
        self.assertEqual(block['failure_fields_available'], 'failure_count' in Cron._fields)
        job = [j for j in block['jobs'] if j['id'] == late.id]
        self.assertTrue(job, block)
        self.assertEqual(job[0]['state'], 'late')
        self.assertGreater(job[0]['lateness_seconds'], 1100)
        self.assertGreaterEqual(block['late_count'], 1)
        if block['failure_fields_available']:
            self.assertEqual(job[0]['failure_count'], 3)
            self.assertGreaterEqual(block['failing_count'], 1)
        else:
            self.assertIsNone(job[0]['failure_count'])
            self.assertIsNone(block['failing_count'])

    def test_own_cron_excluded_and_repeating(self):
        own = self.env.ref('fivenines_monitoring.ir_cron_fivenines_push')
        self.assertTrue(own.active)
        self.assertEqual((own.interval_number, own.interval_type), (1, 'minutes'))
        if 'numbercall' in own._fields:
            self.assertEqual(own.numbercall, -1)
        block = self.monitor._fn_collect_crons()
        self.assertNotIn(own.id, [j['id'] for j in block['jobs']])

    def test_database_block(self):
        block = self.monitor._fn_collect_database()
        self.assertGreater(block['size_bytes'], 0)
        self.assertGreaterEqual(block['connections']['total'], 1)
        self.assertGreater(block['server_max_connections'], 0)


@tagged('post_install', '-at_install', 'fivenines')
class TestSettings(FiveninesCase, TransactionCase):

    def test_settings_roundtrip_and_buttons(self):
        self.icp.set_param(fm.P_KEY, False)
        settings = self.env['res.config.settings'].create({
            'fivenines_enrollment_key': self.key,
            'fivenines_api_url': self.stub.url,
        })
        self.assertEqual(settings.fivenines_key_source, 'Settings (this database)')
        action = settings.action_fivenines_push_now()
        self.assertEqual(action['tag'], 'display_notification')
        self.assertEqual(action['params']['type'], 'success', action)
        self.assertEqual(self.icp.get_param(fm.P_KEY), self.key)
        fresh = self.env['res.config.settings'].create({})
        self.assertTrue(fresh.fivenines_state.startswith('Enrolled'), fresh.fivenines_state)
        self.assertTrue(fresh.fivenines_last_push)
        self.assertEqual(fresh.fivenines_instance_id, self.icp.get_param(fm.P_INSTANCE))
        action = fresh.action_fivenines_reenroll()
        self.assertEqual(action['params']['type'], 'success', action)
        self.assertEqual(len(self.stub_requests('enroll')), 2)

    def test_non_admin_cannot_push(self):
        user = self.env['res.users'].create({
            'name': 'Fivenines no admin', 'login': 'fn_noadmin_%s' % secrets.token_hex(3),
            'groups_id' if 'groups_id' in self.env['res.users']._fields else 'group_ids':
                [(6, 0, [self.env.ref('base.group_user').id])],
        })
        settings = self.env['res.config.settings'].create({})
        with self.assertRaises(AccessError):
            settings.with_user(user).action_fivenines_push_now()


@tagged('post_install', '-at_install', 'fivenines')
class TestHttpCapture(FiveninesCase, HttpCase):
    """Real requests through Odoo's HTTP server, counted by the handler."""

    def test_requests_are_counted(self):
        dbname = self.env.cr.dbname
        self.assertIn(dbname, COLLECTOR.dbs)
        COLLECTOR.install()
        if COLLECTOR.werkzeug_capture == 'disabled':
            self.skipTest('werkzeug logging disabled in this run')
        self.run_push()  # enroll + baseline
        before = (COLLECTOR.snapshot(dbname) or stats.empty_stats())['http']['status']['2xx']
        for _i in range(3):
            self.url_open('/web/login')
        self.url_open('/fivenines-test-no-such-page')
        deadline = time.time() + 10
        while time.time() < deadline:
            snap = COLLECTOR.snapshot(dbname) or stats.empty_stats()
            if snap['http']['status']['2xx'] - before >= 3 and snap['http']['status']['4xx'] >= 1:
                break
            time.sleep(0.1)
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        http = self.last_payload()['http']
        self.assertGreaterEqual(http['requests_by_status']['2xx'], 3, http)
        self.assertGreaterEqual(http['requests_by_status']['4xx'], 1, http)
        self.assertGreater(http['sql_queries_total'], 0)
        self.assertIsNotNone(http['latency_ms']['p50'])
        self.assertEqual(http['timed_requests'], http['requests_total'])
