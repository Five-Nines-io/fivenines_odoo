# Part of Fivenines Monitoring. License LGPL-3.
"""Enrollment, push and error handling against the stub server."""

import hashlib
import json
import logging
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from datetime import timedelta
from unittest.mock import patch

import requests

from odoo import fields, release
from odoo.exceptions import AccessError
from odoo.tools import mute_logger
from odoo.tests.common import HttpCase, TransactionCase, tagged

from ..lib import client as fn_client
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
        warnings = patch.dict(fm._last_warning, clear=True)  # _warn rate limit
        warnings.start()
        self.addCleanup(warnings.stop)
        self.icp = self.env['ir.config_parameter'].sudo()
        for k in fm.STATE_PARAMS + (fm.P_KEY, fm.P_PAUSED, fm.P_API_URL):
            fm.icp_set(self.icp, k, False)
        fm.icp_set(self.icp, fm.P_API_URL, self.stub.url)
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        fm.icp_set(self.icp, 'web.base.url', 'https://erp.example.com')
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
                'logger': 'odoo.x', 'level': 'ERROR', 'message_template': 'boom %s',
                'exception_type': 'ValueError', 'exception_origin': None, 'location': 'x.py:1'},
                {'message': 'boom for order SO042', 'traceback': 'Traceback ...\nValueError: SO042',
                 'at': time.time()})
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
        self.assertTrue(fm.icp_get(self.icp, fm.P_SECRET))
        instance_id = fm.icp_get(self.icp, fm.P_INSTANCE)
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

    def test_key_is_used_once(self):
        # Value: protects=a key pasted in Settings is removed after a successful enrollment and the secret keeps the API that issued it; fails_when=the module keeps the organization key in the database; why_new=#7 (founder decision); seam=none; no_claim=odoo.conf keys (never written)
        self.assertEqual(self.run_push()['result'], 'pushed')
        self.assertIsNone(fm.icp_get(self.icp, fm.P_KEY))
        self.assertEqual(fm.icp_get(self.icp, fm.P_ENDPOINT), self.stub.url)
        record = list(self.stub.state.instances.values())[0]
        self.assertEqual(record['credential'], 'enrollment_key')
        # later pushes need no key
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_enroll_request_shape(self):
        self.run_push()
        inst = self.stub.state.instances
        self.assertEqual(len(inst), 1)
        record = list(inst.values())[0]
        self.assertEqual(record['reason'], 'first_enrollment')
        self.assertIsNone(record['previous_instance_id'])
        comps = record['fingerprint_components']
        self.assertEqual(set(comps), {'database', 'database_uuid', 'base_url', 'odoo_stage', 'neutralized'})
        self.assertFalse(comps['neutralized'])
        self.assertEqual(record['urls'], ['https://erp.example.com'])

    def test_no_key_no_request(self):
        fm.icp_set(self.icp, fm.P_KEY, False)
        with patch.dict(os.environ, {'FIVENINES_ENROLLMENT_KEY': ''}):
            out = self.run_push()
        self.assertEqual(out['result'], 'no_key')
        self.assertEqual(self.stub.state.requests, [])

    def test_key_from_environment(self):
        fm.icp_set(self.icp, fm.P_KEY, False)
        env_conf = patch.object(fm, '_conf', side_effect=lambda name, env: (
            (os.environ.get(env), 'environment') if os.environ.get(env) else (None, None)))
        with patch.dict(os.environ, {'FIVENINES_ENROLLMENT_KEY': self.key,
                                     'FIVENINES_API_URL': self.stub.url}), env_conf:
            self.assertEqual(self.monitor._fn_enrollment_key({fm.P_KEY: None}), (self.key, 'environment'))
            out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)

    def test_server_wide_key_ignores_database_url(self):
        # Value: protects=a key from odoo.conf/env is never sent to a URL set in one database's settings; fails_when=the db-level api_url wins over the server-wide key's level; why_new=red-team RT3 (tenant admin could receive the org key); seam=none; no_claim=odoo.conf parsing (_conf patched)
        fm.icp_set(self.icp, fm.P_KEY, False)
        fm.icp_set(self.icp, fm.P_API_URL, 'https://attacker.example.com')
        env_conf = patch.object(fm, '_conf', side_effect=lambda name, env: (
            (os.environ.get(env), 'environment') if os.environ.get(env) else (None, None)))
        with patch.dict(os.environ, {'FIVENINES_ENROLLMENT_KEY': self.key,
                                     'FIVENINES_API_URL': self.stub.url}), env_conf:
            self.assertEqual(self.monitor._fn_api_url(self.monitor._fn_params(), 'environment'),
                             self.stub.url)
            self.assertEqual(self.run_push()['result'], 'pushed')
        # a key pasted in the database's own settings may use its own URL
        self.assertEqual(self.monitor._fn_api_url({fm.P_API_URL: 'https://own.example.com'}, 'settings'),
                         'https://own.example.com')
        # the settings value, when present, wins over the deployment config
        self.assertEqual(self.monitor._fn_enrollment_key({fm.P_KEY: 'abc'}), ('abc', 'settings'))

    def test_no_key_sweeps_dead_spool_files(self):
        # Value: protects=without a key (nothing pushed) dead process files are removed; fails_when=the sweep runs only while paused, /tmp grows forever; why_new=core review finding, only the paused path was tested; seam=none; no_claim=revoked and refused paths (same helper)
        fm.icp_set(self.icp, fm.P_KEY, False)
        dead = self.fake_process_file(2 ** 22 + 9, 1.0, requests_2xx=1)
        with patch.object(fm, '_conf', return_value=(None, None)):
            self.assertEqual(self.run_push()['result'], 'no_key')
        self.assertFalse(os.path.exists(dead))

    def test_paused(self):
        fm.icp_set(self.icp, fm.P_PAUSED, True)
        # Value: protects=paused run deletes spool files of dead processes, keeps live ones; fails_when=_fn_sweep dropped/inverted, spool grows forever; why_new=sweep untested; seam=none; no_claim=stale-by-age path
        dead = self.fake_process_file(2 ** 22 + 7, 1.0, requests_2xx=1)
        live = self.fake_process_file(os.getpid(), COLLECTOR.started_at, requests_2xx=1)
        self.assertEqual(self.run_push()['result'], 'paused')
        self.assertEqual(self.stub.state.requests, [])
        self.assertFalse(os.path.exists(dead))
        self.assertTrue(os.path.exists(live))

    def test_secret_never_logged_nor_sent_in_body(self):
        capture = _LogCapture()
        root = logging.getLogger()
        root.addHandler(capture)
        old_level = root.level
        root.setLevel(logging.DEBUG)
        try:
            self.run_push()
            secret = fm.icp_get(self.icp, fm.P_SECRET)
            self.fail_next(503)
            self.run_push(force=True)
            requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                          json={'instance_id': fm.icp_get(self.icp, fm.P_INSTANCE)})
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
        fm.icp_set(self.icp, fm.P_API_URL, 'http://api.fivenines.io')
        out = self.run_push()
        self.assertEqual(out['result'], 'config_error')
        self.assertEqual(self.stub.state.requests, [])


@tagged('post_install', '-at_install', 'fivenines')
class TestErrors(FiveninesCase, TransactionCase):

    def test_401_on_push_stops_until_reenroll(self):
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        requests.post(self.stub.url + '/_stub/revoke', json={'instance_id': first}, timeout=5)
        secret = fm.icp_get(self.icp, fm.P_SECRET)
        out = self.run_push()
        self.assertEqual(out['result'], 'revoked')
        self.assertEqual(fm.icp_get(self.icp, fm.P_SECRET), secret, 'kept for the daily retry')
        self.assertGreater(self.state_file()['next_attempt_at'], time.time() + 86000)
        n = len(self.stub.state.requests)
        # the cron neither pushes nor re-enrolls before the daily retry
        self.assertEqual(self.run_push()['result'], 'revoked')
        self.assertEqual(len(self.stub.state.requests), n)
        # "Send now" pushes once more (still refused), but never re-enrolls
        self.assertEqual(self.run_push(force=True)['result'], 'revoked')
        self.assertEqual(self.stub_requests('enroll')[-1:], self.stub_requests('enroll')[:1])
        # Re-enroll needs a key (it was used once): without one, nothing is forgotten
        self.assertEqual(self.run_push(trigger='manual', force=True, reenroll=True)['result'], 'no_key')
        self.assertEqual(fm.icp_get(self.icp, fm.P_SECRET), secret)
        # an administrator pastes a key and re-enrolls explicitly
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        out = self.run_push(trigger='manual', force=True, reenroll=True)
        self.assertEqual(out['result'], 'pushed', out)
        second = fm.icp_get(self.icp, fm.P_INSTANCE)
        self.assertNotEqual(first, second)
        record = self.stub.state.instances[second]
        self.assertEqual(record['reason'], 'manual')
        self.assertEqual(record['previous_instance_id'], first)

    def test_401_heals_when_fivenines_accepts_again(self):
        # Value: protects=a 401 caused by a server-side mistake heals at the daily retry on the same instance; fails_when=401 drops the secret so the whole fleet needs manual re-enroll; why_new=red-team RT9, decision D5; seam=none; no_claim=real 24 h wait (state.json edited)
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        with self.stub.state.lock:
            self.stub.state.instances[first]['revoked'] = True
        self.assertEqual(self.run_push()['result'], 'revoked')
        with self.stub.state.lock:
            self.stub.state.instances[first]['revoked'] = False
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'pushed')
        self.assertEqual(fm.icp_get(self.icp, fm.P_INSTANCE), first)
        self.assertFalse(fm.icp_get(self.icp, fm.P_STATUS))

    def test_live_bodies_match_the_canonical_examples(self):
        # Value: protects=the example bodies next to the schemas have the same structure as what the module sends (enroll with a key, a copy's announcement, a push, a paused heartbeat); fails_when=the module adds or drops a field and the examples the server vendors go stale; why_new=lead request (canonical fixtures); seam=none; no_claim=values
        examples = os.path.join(os.path.dirname(__file__), 'schemas', 'examples')

        def example(name):
            with open(os.path.join(examples, name), encoding='utf-8') as f:
                return json.load(f)

        def same_shape(live, ref, path='$'):
            if isinstance(live, dict) and isinstance(ref, dict):
                self.assertEqual(sorted(live), sorted(ref), path)
                for k in live:
                    same_shape(live[k], ref[k], '%s.%s' % (path, k))
            elif isinstance(live, list) and isinstance(ref, list) and live and ref:
                same_shape(live[0], ref[0], path + '[0]')

        self.run_push()
        same_shape(self.stub.state.enroll_bodies[-1], example('enroll_with_key.json'))
        same_shape(self.last_payload(), example('push_full.json'))
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        self.run_push()
        same_shape(self.stub.state.enroll_bodies[-1], example('enroll_copy_with_secret.json'))
        fm.icp_set(self.icp, fm.P_PAUSED, True)
        out = self.run_push(trigger='manual', force=True)
        self.assertEqual(out.get('heartbeat'), 'pending', out)  # the copy waits for approval
        same_shape(self.stub.state.heartbeats[-1]['body'], example('heartbeat_paused.json'))

    def test_paused_heartbeat(self):
        # Value: protects=while paused, the module sends a slow heartbeat with no metrics (Fivenines shows Paused, not "stopped sending"), never from a copy, at once on Send now, and resumes with a fresh baseline so nothing of the paused period is sent; fails_when=a paused module is silent, sends metrics, heartbeats every minute, or a copy marks the original paused; why_new=#10; seam=state.json pace moved back; no_claim=the server's Paused display
        self.run_push()
        pushes = len(self.stub.state.pushes)
        fm.icp_set(self.icp, fm.P_PAUSED, True)
        out = self.run_push()
        self.assertEqual((out['result'], out.get('heartbeat')), ('paused', 'sent'), out)
        self.assertEqual(len(self.stub.state.heartbeats), 1)
        body = self.stub.state.heartbeats[-1]['body']
        self.assertEqual((body['kind'], body['state'], body['every_seconds']), ('heartbeat', 'paused', 900))
        self.assertNotIn('http', body)
        self.assertEqual(self.stub.state.schema_errors, [])
        self.assertEqual(len(self.stub.state.pushes), pushes, 'no metrics while paused')
        self.assertEqual(self.run_push().get('heartbeat'), None, 'one heartbeat per 15 minutes')
        self.assertEqual(len(self.stub.state.heartbeats), 1)
        state = self.state_file()
        state['last_heartbeat_at'] -= 900
        spool.write_json_atomic(os.path.join(self.spool_dir, spool.STATE_FILE), state)
        self.assertEqual(self.run_push().get('heartbeat'), 'sent')
        self.assertEqual(self.run_push(trigger='manual', force=True).get('heartbeat'), 'sent', 'Send now')
        self.assertEqual(len(self.stub.state.heartbeats), 3)
        # a copy of the paused database carries the secret but stays silent
        uuid_ = fm.icp_get(self.icp, 'database.uuid')
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        self.assertIsNone(self.run_push(trigger='manual', force=True).get('heartbeat'))
        self.assertEqual(len(self.stub.state.heartbeats), 3)
        fm.icp_set(self.icp, 'database.uuid', uuid_)
        # counted while paused, by a live process: not sent after the resume
        self.fake_process_file(os.getpid(), COLLECTOR.started_at, requests_2xx=5)
        fm.icp_set(self.icp, fm.P_PAUSED, False)
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        payload = self.last_payload()
        self.assertEqual(payload['kind'], 'metrics')
        self.assertTrue(payload['window']['baseline_reset'])
        self.assertEqual(payload['seq'], 1)
        self.assertEqual(payload['http']['requests_by_status']['2xx'], 0)

    def test_stub_rule1_fresh_install_adopts_the_first_url_change(self):
        # Value: protects=a fresh install whose admin logs in during the first minutes (1 or 2 accepted pushes, same identity and stream) gets its URL change adopted, not a false copy; a mismatch inside the 3-push window is a 409; fails_when=rule 1 demands 3 pushes, or ignores a foreign push in the window; why_new=lead's rule-1 wording (revision 2); seam=pushes built from the module's payload; no_claim=the real server
        self.run_push()
        secret = fm.icp_get(self.icp, fm.P_SECRET)
        record = self.stub.state.instances[fm.icp_get(self.icp, fm.P_INSTANCE)]
        mine = json.loads(json.dumps(self.last_payload()))
        client = fn_client.Client(self.stub.url, 'test')

        def push(payload, seq, fingerprint):
            payload = json.loads(json.dumps(payload))
            payload['seq'], payload['instance']['fingerprint'] = seq, fingerprint
            return client.push(secret, payload).status

        # 1 accepted push, same place: adopted
        self.assertEqual(len(record['recent_places']), 1)
        self.assertEqual(push(mine, 2, 'a' * 64), 200)
        self.assertEqual(record['fingerprint'], 'a' * 64)
        # 2 accepted pushes, same place: adopted
        self.assertEqual(push(mine, 3, 'b' * 64), 200)
        self.assertEqual(record['fingerprint'], 'b' * 64)
        # a foreign stream inside the window: 409 for a change, from anyone
        other = dict(mine, stream_id='c' * 32)
        self.assertEqual(push(other, 1, 'b' * 64), 200, 'same fingerprint: accepted')
        self.assertEqual(push(mine, 4, 'd' * 64), 409)
        self.assertEqual(record['fingerprint'], 'b' * 64)

    def test_reenroll_while_paused_forgets_nothing(self):
        # Value: protects=Re-enroll while paused keeps the secret and instance; fails_when=the reenroll branch runs before the pause check; why_new=state-machine finding SM2; seam=none; no_claim=UI button path (model call)
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        fm.icp_set(self.icp, fm.P_PAUSED, True)
        self.assertEqual(self.run_push(trigger='manual', force=True, reenroll=True)['result'], 'paused')
        self.assertEqual(fm.icp_get(self.icp, fm.P_INSTANCE), first)
        self.assertTrue(fm.icp_get(self.icp, fm.P_SECRET))

    def test_failed_reenroll_keeps_reason_and_previous(self):
        # Value: protects=after a failed enrollment for a copy the retry still says fingerprint_changed with previous_instance_id; fails_when=the reason is lost and the retry looks like a dedupable first_enrollment; why_new=state-machine finding SM3; seam=none; no_claim=409/manual paths (same pending_enroll)
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        self.fail_next(503, path='enroll')
        self.assertEqual(self.run_push()['result'], 'enroll_failed')
        self.assertEqual(fm.icp_get(self.icp, fm.P_INSTANCE), first, 'kept until a new enrollment succeeds')
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'pending')
        record = self.stub.state.instances[fm.icp_get(self.icp, fm.P_INSTANCE)]
        self.assertEqual((record['reason'], record['previous_instance_id']), ('fingerprint_changed', first))

    def test_401_on_enroll_waits_for_a_new_key(self):
        fm.icp_set(self.icp, fm.P_KEY, 'f' * 64)
        out = self.run_push()
        self.assertEqual(out['result'], 'enrollment_refused')
        n = len(self.stub.state.requests)
        self.assertEqual(self.run_push()['result'], 'enrollment_refused')
        self.assertEqual(len(self.stub.state.requests), n)  # no retry with the same key
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_409_reenrolls_as_new_instance(self):
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        self.fail_next(409)
        out = self.run_push()
        self.assertEqual(out['result'], 'conflict')
        self.assertEqual((out['enroll'], out['state']), ('enrolled', 'pending'))
        second = fm.icp_get(self.icp, fm.P_INSTANCE)
        self.assertNotEqual(first, second)
        record = self.stub.state.instances[second]
        self.assertEqual((record['reason'], record['credential'], record['previous_instance_id']),
                         ('conflict', 'instance_secret', first))
        # proposed in Fivenines; once accepted it pushes
        requests.post(self.stub.url + '/_stub/accept', json={'instance_id': second}, timeout=5)
        self.expire_backoff()
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

    def test_stream_id_changes_with_a_baseline_reset(self):
        # Value: protects=seq restarts only together with a new stream_id, so (stream_id, seq) dedup never drops data; fails_when=seq restarts at 1 with the same stream after state.json is lost; why_new=red-team RT5; seam=none; no_claim=server dedup itself
        self.run_push()
        self.run_push()
        stream = self.last_payload()['stream_id']
        self.assertEqual(self.last_payload()['seq'], 2)
        os.unlink(os.path.join(self.spool_dir, spool.STATE_FILE))  # reboot wiped /tmp
        self.run_push()
        p = self.last_payload()
        self.assertEqual(p['seq'], 1)
        self.assertTrue(p['window']['baseline_reset'])
        self.assertNotEqual(p['stream_id'], stream)

    def test_failing_sql_collector_does_not_abort_the_run(self):
        # Value: protects=a failing SQL collector nulls its block, the transaction stays usable and the push goes out; fails_when=guard catches the SQL error without a savepoint (InFailedSqlTransaction later); why_new=red-team RT11; seam=none; no_claim=statement_timeout itself (a bad query stands in)
        self.run_push()

        def broken(self_):
            self_.env.cr.execute('SELECT no_such_column FROM ir_cron')

        # odoo.sql_db logs the bad query at ERROR: expected here, muted
        with patch.object(self.registry['fivenines.monitor'], '_fn_collect_crons', broken), \
                mute_logger('odoo.sql_db'):
            self.assertEqual(self.run_push()['result'], 'pushed')
        p = self.last_payload()
        self.assertIsNone(p['crons'])
        self.assertEqual([e['collector'] for e in p['collector_errors']], ['crons'])
        self.assertIsNotNone(p['database'], 'later queries still run')

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
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        # a copy made by Odoo's duplicate/restore-as-copy gets a new uuid
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        self.assertIsNone(fm.icp_get(self.icp, fm.P_KEY), 'no key: the copy uses the secret it carries')
        out = self.run_push()
        self.assertEqual(out['result'], 'pending', out)
        second = fm.icp_get(self.icp, fm.P_INSTANCE)
        self.assertNotEqual(first, second)
        record = self.stub.state.instances[second]
        self.assertEqual((record['reason'], record['credential'], record['changed']),
                         ('fingerprint_changed', 'instance_secret', ['database_uuid']))
        self.assertEqual(record['previous_instance_id'], first)
        self.assertEqual(self.stub.state.instances[first]['state'], 'monitored', 'the original is untouched')

    def test_failed_copy_announcement_backs_off(self):
        # Value: protects=a copy announces itself at once even while the original backs off, but its own failed announcements follow the bounded backoff (contract s7); fails_when=every copy calls /enroll every minute while Fivenines is down, or a copy waits for the original's schedule; why_new=lead review of revision 2; seam=none; no_claim=real outage timings
        self.run_push()
        self.fail_next(503)
        self.assertEqual(self.run_push()['result'], 'push_failed')
        self.assertGreater(self.state_file()['next_attempt_at'], time.time(), 'the original backs off')
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        self.fail_next(503, count=10, path='enroll')
        self.assertEqual(self.run_push()['result'], 'enroll_failed', "no wait for the original's backoff")
        announced = len(self.stub_requests('enroll'))
        fm.icp_set(self.icp, 'web.base.url', 'https://copy.example.com')  # admin login: same copy
        self.assertEqual(self.run_push()['result'], 'backoff')
        self.assertEqual(len(self.stub_requests('enroll')), announced)
        for failures in (2, 3, 4):
            out = self.run_push()
            self.assertEqual(out['result'], 'backoff', out)
            self.assertEqual(len(self.stub_requests('enroll')), announced, 'no request during the backoff')
            self.expire_backoff()
            self.assertEqual(self.run_push()['result'], 'enroll_failed')
            announced += 1
            self.assertEqual(len(self.stub_requests('enroll')), announced)
            self.assertEqual(self.state_file()['failures'], failures + 1)
        # after 5 failures in a row the next announcement is 4 minutes away
        self.assertGreater(self.state_file()['next_attempt_at'], time.time() + 200)
        self.expire_backoff()
        self.stub.state.failures.clear()
        out = self.run_push()
        self.assertEqual(out['result'], 'pending', out)
        self.assertNotIn('backoff_fingerprint', self.state_file())

    def test_new_public_url_is_adopted_until_acked(self):
        # Value: protects=a base_url-only change (admin login via an alias) keeps the instance and is flagged until a push is acked; fails_when=a URL change re-enrolls, or a failed push loses the flag and the 409 rule splits the instance; why_new=red-team RT2 + state-machine SM1, decision D3; seam=none; no_claim=real admin login (param set directly)
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        fm.icp_set(self.icp, 'web.base.url', 'https://alias.example.com')
        self.fail_next(503)
        self.assertEqual(self.run_push()['result'], 'push_failed')
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'pushed')
        self.assertEqual(fm.icp_get(self.icp, fm.P_INSTANCE), first)
        self.assertEqual(self.last_payload()['instance']['fingerprint_change'], 'base_url_changed')
        self.run_push()
        self.assertIsNone(self.last_payload()['instance']['fingerprint_change'])
        self.assertEqual(len(self.stub_requests('enroll')), 1)

    def test_stub_409_rule(self):
        # Value: protects=the reference server answers 409 to a changed fingerprint from another running server, even after the old place has been silent for over 15 minutes, and adopts it from the same server; fails_when=the contract's s5 rule is not implemented as documented, or a silence lets another place take over; why_new=decision D3, then the founder's rule "a copy is proposed, never added"; seam=none; no_claim=the real fivenines-server
        self.run_push()
        secret = fm.icp_get(self.icp, fm.P_SECRET)
        record = self.stub.state.instances[fm.icp_get(self.icp, fm.P_INSTANCE)]
        payload = json.loads(json.dumps(self.last_payload()))
        payload['instance']['fingerprint'] = 'f' * 64
        payload['process']['pid'] = payload['process']['pid'] + 1  # another server
        r = fn_client.Client(self.stub.url, 'test').push(secret, payload)
        self.assertEqual(r.status, 409)
        record['last_push_at'] -= 3600  # the old place has been silent for an hour
        r = fn_client.Client(self.stub.url, 'test').push(secret, payload)
        self.assertEqual(r.status, 409, 'never adopted on silence alone')
        payload['process']['pid'] = self.last_payload()['process']['pid']  # same server
        r = fn_client.Client(self.stub.url, 'test').push(secret, payload)
        self.assertEqual(r.status, 200)

    def test_same_fingerprint_copy_pushing_last_cannot_take_production(self):
        # Value: protects=a PostgreSQL-level copy with production's fingerprint, accepted alongside production, cannot move production's instance when its admin logs in: rule 1 adopts a URL change only from the same identity and stream over the last 3 accepted pushes; fails_when=rule 1 trusts the last accepted push alone and production then lands as the pending copy; why_new=lead decision on the rule-1 TODO; seam=pushes built from the module's payload with another identity and stream; no_claim=the real server
        self.run_push()
        secret = fm.icp_get(self.icp, fm.P_SECRET)
        record = self.stub.state.instances[fm.icp_get(self.icp, fm.P_INSTANCE)]
        production = json.loads(json.dumps(self.last_payload()))
        client = fn_client.Client(self.stub.url, 'test')

        def push(payload, seq):
            payload = json.loads(json.dumps(payload))
            payload['seq'] = seq
            return client.push(secret, payload).status

        copy = json.loads(json.dumps(production))
        copy['instance']['hostname'] = 'restored-copy'
        copy['process']['pid'] += 1000
        copy['stream_id'] = 'f' * 32
        for seq in (2, 3):
            self.assertEqual(push(production, seq), 200)
        self.assertEqual(push(copy, 1), 200, 'same fingerprint: accepted alongside production')
        # the copy's admin logs in: Odoo rewrites web.base.url, the copy pushes last
        moved = json.loads(json.dumps(copy))
        components = dict(moved['instance']['fingerprint_components'], base_url='https://copy.example.com')
        moved['instance']['fingerprint_components'] = components
        moved['instance']['fingerprint'] = hashlib.sha256(
            json.dumps(components, sort_keys=True).encode()).hexdigest()
        self.assertEqual(push(moved, 2), 409, 'one push from that place is not a stable place')
        self.assertEqual(record['fingerprint'], production['instance']['fingerprint'])
        self.assertEqual(push(production, 4), 200, 'production keeps its instance')
        # the same server, stable over 3 pushes, may still change its URL (rule 1)
        for seq in (5, 6):
            self.assertEqual(push(production, seq), 200)
        stable = json.loads(json.dumps(production))
        stable['instance']['fingerprint_components'] = dict(components, database=production['instance']['database'])
        stable['instance']['fingerprint'] = 'e' * 64
        self.assertEqual(push(stable, 7), 200)
        self.assertEqual(record['fingerprint'], 'e' * 64)

    def test_restore_elsewhere_while_original_is_down_is_only_proposed(self):
        # Value: protects=a production database restored on a test server while production is silent does not take over production's identity: it is proposed (pending) and the original keeps its fingerprint and token; a move is never guessed; fails_when=the server adopts a new place after 15 minutes of silence; why_new=lead review of revision 2 (founder rule); seam=the other place's identity is set on the stub record; no_claim=the real fivenines-server UI ("Replaces an existing database")
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        original = self.stub.state.instances[first]
        fingerprint = original['fingerprint']
        original['recent_places'] = [[['production-host', 1, 1.0], 'prod-stream']]  # the last push came from elsewhere
        original['last_push_at'] -= 1200  # and production has been silent for 20 minutes
        fm.icp_set(self.icp, 'web.base.url', 'https://test-server.example.com')  # admin login on the test server
        out = self.run_push()
        self.assertEqual((out['result'], out['state']), ('conflict', 'pending'), out)
        proposal = fm.icp_get(self.icp, fm.P_INSTANCE)
        self.assertNotEqual(proposal, first)
        record = self.stub.state.instances[proposal]
        self.assertEqual((record['copy_of'], record['reason'], record['state']),
                         (first, 'conflict', 'pending'))
        self.assertEqual((original['state'], original['fingerprint']), ('monitored', fingerprint),
                         'production keeps its identity')
        self.assertFalse(original['revoked'])

    def test_url_change_from_localhost_is_adopted(self):
        fm.icp_set(self.icp, 'web.base.url', 'http://localhost:8069')
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        fm.icp_set(self.icp, 'web.base.url', 'https://ERP.example.com:443/')
        out = self.run_push()
        self.assertEqual(out['result'], 'pushed', out)
        self.assertEqual(first, fm.icp_get(self.icp, fm.P_INSTANCE))
        payload = self.last_payload()
        self.assertEqual(payload['instance']['fingerprint_change'], 'base_url_changed')
        self.assertEqual(payload['instance']['base_url'], 'https://erp.example.com')
        self.assertEqual(len(self.stub_requests('enroll')), 1)

    def test_copy_of_revoked_instance_can_enroll(self):
        self.run_push()
        requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                      json={'instance_id': fm.icp_get(self.icp, fm.P_INSTANCE)})
        self.assertEqual(self.run_push()['result'], 'revoked')
        fm.icp_set(self.icp, 'database.uuid', 'copy-of-revoked')
        # no wait for the original's daily retry: the copy is detected first;
        # its copied secret is revoked, so it needs a key
        self.assertEqual(self.run_push()['result'], 'no_key')
        self.assertEqual(json.loads(fm.icp_get(self.icp, fm.P_STATUS))['state'], 'copy_needs_key')
        n = len(self.stub.state.requests)  # it waits for a key without requests (review)
        for _i in range(3):
            self.expire_backoff()
            self.assertEqual(self.run_push()['result'], 'no_key')
        self.assertEqual(len(self.stub.state.requests), n, 'no request while it needs a key')
        fm.icp_set(self.icp, 'web.base.url', 'https://staging.example.com')  # admin login
        self.assertEqual(self.run_push()['result'], 'no_key')
        self.assertEqual(len(self.stub.state.requests), n, 'still the same copy')
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        self.assertEqual(self.run_push()['result'], 'pushed')
        record = self.stub.state.instances[fm.icp_get(self.icp, fm.P_INSTANCE)]
        self.assertEqual((record['credential'], record['reason']), ('enrollment_key', 'fingerprint_changed'))

    def test_copy_key_fallback_never_goes_to_the_stored_endpoint(self):
        # Value: protects=when a copy's secret is refused, the enrollment key goes to the URL of its own level, never to fivenines.endpoint (a database parameter an admin can edit, or that a restored dump carries); fails_when=a tenant admin points the endpoint at their host, answers 401, and receives the organization's key; why_new=review of revision 2 (security, red team, adversarial); seam=a second stub plays the foreign endpoint; no_claim=TLS
        self.run_push()
        other = StubServer([]).start()  # knows no secret: answers 401
        try:
            fm.icp_set(self.icp, fm.P_ENDPOINT, other.url)
            fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
            fm.icp_set(self.icp, fm.P_KEY, self.key)
            out = self.run_push()
            self.assertEqual(out['result'], 'pushed', out)
            self.assertEqual([r['path'] for r in other.state.requests], ['enroll'],
                             'only the copied secret went to the stored endpoint')
            instance = fm.icp_get(self.icp, fm.P_INSTANCE)
            self.assertEqual(self.stub.state.instances[instance]['credential'], 'enrollment_key')
            self.assertEqual(fm.icp_get(self.icp, fm.P_ENDPOINT), self.stub.url)
            self.assertEqual(self.stub.state.pushes[-1]['instance_id'], instance,
                             'the new secret is pushed to the API that issued it')
        finally:
            other.stop()

    def test_key_pasted_after_enrollment_is_kept_until_used(self):
        # Value: protects=a key pasted to Re-enroll a revoked database survives a Send now (only the key an enrollment already used is dropped); fails_when=Send now erases the new key and Re-enroll answers no_key; why_new=review of revision 2 (testing, adversarial); seam=enrolled_at moved back (one test transaction); no_claim=a real rollback
        self.run_push()
        requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                      json={'instance_id': fm.icp_get(self.icp, fm.P_INSTANCE)})
        self.assertEqual(self.run_push()['result'], 'revoked')
        fm.icp_set(self.icp, fm.P_ENROLLED_AT, str(int(time.time()) - 2 * 86400))  # enrolled days ago
        fm.icp_set(self.icp, fm.P_KEY, self.key)  # pasted now
        self.assertEqual(self.run_push(trigger='manual', force=True)['result'], 'revoked')
        self.assertEqual(fm.icp_get(self.icp, fm.P_KEY), self.key, 'kept for Re-enroll')
        self.assertEqual(self.run_push(trigger='manual', force=True, reenroll=True)['result'], 'pushed')
        self.assertIsNone(fm.icp_get(self.icp, fm.P_KEY), 'used once')

    def test_copy_with_a_refused_key_stays_silent(self):
        # Value: protects=a copy whose copied secret and key are both refused waits for another key without calling /enroll every minute; fails_when=the copy re-announces each run; why_new=review fix-check (red team); seam=none; no_claim=none
        self.run_push()
        requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                      json={'instance_id': fm.icp_get(self.icp, fm.P_INSTANCE)})
        requests.post(self.stub.url + '/_stub/revoke_key', json={'key': self.key}, timeout=5)
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        self.assertEqual(self.run_push()['result'], 'enrollment_refused')
        n = len(self.stub.state.requests)
        for _i in range(3):
            self.expire_backoff()
            self.assertEqual(self.run_push()['result'], 'enrollment_refused')
        self.assertEqual(len(self.stub.state.requests), n, 'no request until the key changes')

    def test_stub_keeps_distinct_conflict_copies_apart(self):
        # Value: protects=two places that drew a 409 for one instance get two proposals, not one shared token (their copy components equal the original's); fails_when=the stub merges them on copy components; why_new=review fix-check (red team); seam=none; no_claim=the real server
        self.run_push()
        secret = fm.icp_get(self.icp, fm.P_SECRET)
        body = self.stub.state.instances[fm.icp_get(self.icp, fm.P_INSTANCE)]
        ids = []
        for url in ('https://node-a.example.com', 'https://node-b.example.com'):
            components = dict(body['fingerprint_components'], base_url=url)
            instance = dict(self.last_payload()['instance'], base_url=url, fingerprint_components=components,
                            fingerprint=hashlib.sha256(json.dumps(components, sort_keys=True).encode()).hexdigest())
            for k in ('instance_id', 'fingerprint_change'):
                instance.pop(k, None)
            r = fn_client.Client(self.stub.url, 'test').enroll(secret, {
                'schema_version': 1, 'credential': 'instance_secret', 'reason': 'conflict',
                'previous_instance_id': body['instance_id'], 'changed': [], 'key_source': None,
                'instance': instance})
            self.assertEqual(r.status, 202, r.data)
            ids.append(r.data['instance_id'])
        self.assertNotEqual(ids[0], ids[1])

    def test_key_is_dropped_when_the_database_does_not_need_one(self):
        # Value: protects=the organization key is never kept on a database that does not need it (pasted on a healthy enrolled database, or left by an enrollment that rolled back); fails_when=a pasted key stays in ir.config_parameter and travels with every dump; why_new=review pass 2 (security, testing); seam=enrolled_at moved (one test transaction); no_claim=a real rollback
        self.run_push()
        fm.icp_set(self.icp, fm.P_ENROLLED_AT, str(int(time.time()) - 2 * 86400))
        fm.icp_set(self.icp, fm.P_KEY, self.key)  # pasted on a healthy database
        self.assertEqual(self.run_push()['result'], 'pushed')
        self.assertIsNone(fm.icp_get(self.icp, fm.P_KEY))
        # revoked, with the key the enrollment used still there (its deletion rolled back)
        requests.post(self.stub.url + '/_stub/revoke', timeout=5,
                      json={'instance_id': fm.icp_get(self.icp, fm.P_INSTANCE)})
        self.assertEqual(self.run_push()['result'], 'revoked')
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        fm.icp_set(self.icp, fm.P_ENROLLED_AT, str(int(time.time()) + 60))  # the key predates it
        self.assertEqual(self.run_push(trigger='manual', force=True)['result'], 'revoked')
        self.assertIsNone(fm.icp_get(self.icp, fm.P_KEY))

    def test_server_name_is_bounded(self):
        self.assertEqual(len(fm._server_name({'name': 'x' * 500})), fm.MAX_SERVER_NAME)
        self.assertIsNone(fm._server_name(None))
        self.assertIsNone(fm._server_name('not a dict'))
        self.assertIsNone(fm._server_name({}))

    def test_neutralized_copy_stays_silent_until_turned_on(self):
        # Value: protects=Odoo's neutralization is respected (the cron stays off, the secret is kept) and one click turns monitoring on, after which the copy announces itself with the copied secret and lands as proposed; fails_when=neutralize deletes the secret, or the module re-activates its cron by itself; why_new=#7 (founder decision); seam=none; no_claim=Odoo.sh's own staging build
        from odoo.modules import neutralize
        self.run_push()
        first = fm.icp_get(self.icp, fm.P_INSTANCE)
        secret = fm.icp_get(self.icp, fm.P_SECRET)
        neutralize.neutralize_database(self.env.cr)
        self.env.invalidate_all() if hasattr(self.env, 'invalidate_all') else self.env.cache.invalidate()
        transaction = getattr(self.env, 'transaction', None)
        if hasattr(transaction, 'invalidate_ormcache'):  # 20.0
            for group in ('default', 'stable'):
                transaction.invalidate_ormcache(group)
        elif hasattr(self.env.registry, 'clear_cache'):  # 17.0-19.0
            for group in ('default', 'stable'):
                try:
                    self.env.registry.clear_cache(group)
                except (KeyError, TypeError):
                    pass
        else:  # 16.0
            self.env.registry.clear_caches()
        self.assertEqual(fm.icp_get(self.icp, fm.P_SECRET), secret, 'the copy keeps the secret')
        cron = self.env.ref('fivenines_monitoring.ir_cron_fivenines_push')
        self.assertFalse(cron.active, 'Odoo neutralization deactivates every cron, ours included')
        settings = self.env['res.config.settings'].create({})
        self.assertIn('neutralized copy', settings.fivenines_state)
        # one click: the cron runs again, the copy announces itself
        action = settings.action_fivenines_turn_on()
        self.assertTrue(cron.active)
        self.assertEqual(action['params']['type'], 'warning', action)  # pending
        second = fm.icp_get(self.icp, fm.P_INSTANCE)
        record = self.stub.state.instances[second]
        self.assertNotEqual(second, first)
        self.assertEqual((record['state'], record['credential'], record['changed']),
                         ('pending', 'instance_secret', ['neutralized']))
        self.assertEqual(record['previous_instance_id'], first)

    def test_normalize_url(self):
        self.assertEqual(fm.normalize_url('HTTPS://Erp.Example.com:443/'), 'https://erp.example.com')
        self.assertEqual(fm.normalize_url('http://h:8069/odoo/'), 'http://h:8069/odoo')
        self.assertIsNone(fm.normalize_url(''))


@tagged('post_install', '-at_install', 'fivenines')
class TestApproval(FiveninesCase, TransactionCase):
    """#4: a new database can be proposed (Monitor / Ignore) instead of added."""

    def setUp(self):
        super().setUp()
        requests.post(self.stub.url + '/_stub/policy', json={'new': 'pending', 'retry_after': 900},
                      timeout=5)

    def test_pending_then_accepted(self):
        # Value: protects=a held enrollment keeps its credentials, checks only every retry_after, accumulates nothing, and resumes minute pushes once accepted; fails_when=the module pushes every minute while pending, loses the token, or resends what was counted while pending; why_new=#4; seam=none; no_claim=the real server's acceptance UI
        out = self.run_push()
        self.assertEqual(out['result'], 'pending', out)
        instance = fm.icp_get(self.icp, fm.P_INSTANCE)
        status = json.loads(fm.icp_get(self.icp, fm.P_STATUS))
        self.assertEqual(status['state'], 'pending')
        self.assertTrue(status['name'])
        self.assertGreater(self.state_file()['next_attempt_at'], time.time() + 800)
        settings = self.env['res.config.settings'].create({})
        self.assertIn('Waiting for approval in Fivenines', settings.fivenines_state)
        self.assertIn(status['name'], settings.fivenines_state)
        n = len(self.stub.state.requests)
        self.assertEqual(self.run_push()['result'], 'pending')   # no request before retry_after
        self.assertEqual(len(self.stub.state.requests), n)
        # a pending check: Fivenines stores nothing, counted requests are dropped
        dead = self.fake_process_file(2 ** 22 + 11, 1.0, requests_2xx=4)
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'pending')
        self.assertEqual(self.stub.state.pushes, [])
        self.assertFalse(os.path.exists(dead))
        # accepted in Fivenines: the next check pushes, and keeps pushing every minute
        requests.post(self.stub.url + '/_stub/accept', json={'instance_id': instance}, timeout=5)
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'pushed')
        payload = self.last_payload()
        self.assertTrue(payload['window']['baseline_reset'])
        self.assertEqual(payload['http']['requests_by_status']['2xx'], 0, 'nothing from the pending time')
        self.assertFalse(fm.icp_get(self.icp, fm.P_STATUS))
        self.assertEqual(self.run_push()['result'], 'pushed')

    def test_ignored_is_final(self):
        # Value: protects=Ignored stops every automatic request, shows its own status, and only an explicit Re-enroll with a key proposes the database again; fails_when=the module keeps polling or re-enrolls by itself after Ignore; why_new=#4; seam=none; no_claim=the real server's Ignore
        self.run_push()
        instance = fm.icp_get(self.icp, fm.P_INSTANCE)
        requests.post(self.stub.url + '/_stub/ignore', json={'instance_id': instance}, timeout=5)
        self.expire_backoff()
        out = self.run_push()
        self.assertEqual(out['result'], 'ignored', out)
        self.assertEqual(json.loads(fm.icp_get(self.icp, fm.P_STATUS))['state'], 'ignored')
        n = len(self.stub.state.requests)
        for _i in range(3):
            self.expire_backoff()
            self.assertEqual(self.run_push()['result'], 'ignored')
        self.assertEqual(len(self.stub.state.requests), n, 'no automatic request once ignored')
        settings = self.env['res.config.settings'].create({})
        self.assertIn('Not monitored: ignored in Fivenines', settings.fivenines_state)
        # Send now asks again (still ignored); Re-enroll with a key proposes it anew
        self.assertEqual(self.run_push(force=True)['result'], 'ignored')
        fm.icp_set(self.icp, fm.P_KEY, self.key)
        self.assertEqual(self.run_push(trigger='manual', force=True, reenroll=True)['result'], 'pending')
        self.assertNotEqual(fm.icp_get(self.icp, fm.P_INSTANCE), instance)

    def test_copy_of_an_ignored_copy_stays_ignored(self):
        # Value: protects=a copy announcing itself again after Ignore gets 410, not a new proposal; fails_when=the stub (and so the contract) re-proposes an ignored copy on every announcement; why_new=#4 "Ignore is final for that database"; seam=none; no_claim=server persistence
        requests.post(self.stub.url + '/_stub/policy', json={'new': 'monitored'}, timeout=5)
        self.run_push()
        original_secret = fm.icp_get(self.icp, fm.P_SECRET)
        original_fp = fm.icp_get(self.icp, fm.P_FINGERPRINT)
        original_id = fm.icp_get(self.icp, fm.P_INSTANCE)
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        self.assertEqual(self.run_push()['result'], 'pending')
        copy_id = fm.icp_get(self.icp, fm.P_INSTANCE)
        requests.post(self.stub.url + '/_stub/ignore', json={'instance_id': copy_id}, timeout=5)
        # the same copy rebuilt from the original (e.g. staging refreshed): it
        # carries the original's secret and fingerprint again
        fm.icp_set(self.icp, fm.P_SECRET, original_secret)
        fm.icp_set(self.icp, fm.P_FINGERPRINT, original_fp)
        fm.icp_set(self.icp, fm.P_INSTANCE, original_id)
        fm.icp_set(self.icp, fm.P_STATUS, False)
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'ignored')
        # and it stays silent: no automatic request on the next runs (review)
        n = len(self.stub.state.requests)
        for _i in range(3):
            self.expire_backoff()
            self.assertEqual(self.run_push()['result'], 'ignored')
        self.assertEqual(len(self.stub.state.requests), n, 'an ignored copy makes no request')
        # an admin login on the copy rewrites web.base.url: still the same copy
        fm.icp_set(self.icp, 'web.base.url', 'https://staging.example.com')
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'ignored')
        self.assertEqual(len(self.stub.state.requests), n, 'a base_url change does not re-announce it')
        # Send now still asks
        self.assertEqual(self.run_push(force=True)['result'], 'ignored')
        self.assertEqual(len(self.stub.state.requests), n + 1)

    def test_copy_of_an_ignored_original_still_announces_itself(self):
        # Value: protects=Ignore holds the database it was given for, not its later copies: a copy of an ignored database announces itself and is proposed; fails_when=the hold ignores which copy it was recorded for; why_new=review pass 2 (testing, state-machines); seam=none; no_claim=server policy for copies of ignored databases
        self.run_push()
        requests.post(self.stub.url + '/_stub/ignore', json={'instance_id': fm.icp_get(self.icp, fm.P_INSTANCE)},
                      timeout=5)
        self.expire_backoff()
        self.assertEqual(self.run_push()['result'], 'ignored')
        fm.icp_set(self.icp, 'database.uuid', 'copied-%s' % secrets.token_hex(4))
        n = len(self.stub_requests('enroll'))
        self.assertEqual(self.run_push()['result'], 'pending')
        self.assertEqual(len(self.stub_requests('enroll')), n + 1)


@tagged('post_install', '-at_install', 'fivenines')
class TestPayloadExtras(FiveninesCase, TransactionCase):
    """#5 every URL the database knows, #6 error messages on by default."""

    def test_urls_from_base_url_and_websites(self):
        # Value: protects=base_url comes first, website domains follow normalized (https:// added), without duplicates; fails_when=a scheme-less website domain or a duplicate breaks monitor matching; why_new=#5; seam=none; no_claim=the website module itself (not installed in tests)
        self.assertEqual(fm.urls_from('https://erp.example.com', ['acme.com', 'https://ERP.example.com/',
                                                                  ' shop.acme.com ', '', None]),
                         ['https://erp.example.com', 'https://acme.com', 'https://shop.acme.com'])
        self.assertEqual(fm.urls_from(None, []), [])
        self.run_push()
        self.assertEqual(self.last_payload()['instance']['urls'], ['https://erp.example.com'])

    def test_error_messages_on_by_default_and_switch(self):
        # Value: protects=each error group carries its latest message and traceback by default, and the settings switch sends groups and counts only; fails_when=messages are dropped by default or sent while switched off; why_new=#6 (founder decision); seam=none; no_claim=credential masking (test_lib)
        self.run_push()
        import psutil
        child = subprocess.Popen(['sleep', '60'])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        started = psutil.Process(child.pid).create_time()
        self.fake_process_file(child.pid, started, errors=2)
        self.run_push()
        logs = self.last_payload()['logs']
        self.assertEqual(logs['messages'], 'on')
        group = logs['fingerprints'][0]
        self.assertEqual(group['last_message'], 'boom for order SO042')
        self.assertIn('ValueError', group['last_traceback'])
        self.assertTrue(group['last_seen_at'])
        settings = self.env['res.config.settings'].create({'fivenines_send_error_messages': False})
        settings.set_values()
        self.assertFalse(self.env['res.config.settings'].create({}).fivenines_send_error_messages)
        self.fake_process_file(child.pid, started, errors=3)
        self.run_push()
        logs = self.last_payload()['logs']
        self.assertEqual(logs['messages'], 'off')
        self.assertIsNone(logs['fingerprints'][0]['last_message'])
        self.assertIsNone(logs['fingerprints'][0]['last_traceback'])
        self.assertEqual(logs['error_count'], 1)


@tagged('post_install', '-at_install', 'fivenines')
class TestCounting(FiveninesCase, TransactionCase):

    def test_idle_live_worker_counted_once(self):
        # Value: protects=a live process idle for over an hour keeps its acked baseline, each request counted once; fails_when=a stale-by-age rule drops the baseline of a live process and its history is resent; why_new=QA ISSUE-001 (red-team RT1) reproduced it, no test covered an old file of a live pid; seam=none; no_claim=real prefork worker (a sleep process stands in)
        # Regression proof - fails at HEAD: yes (6 != 1) · passes at base: unavailable (ecosystem) · passes after fix: yes
        import psutil
        self.run_push()
        child = subprocess.Popen(['sleep', '60'])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        started = psutil.Process(child.pid).create_time()
        path = self.fake_process_file(child.pid, started, requests_2xx=5)
        doc = spool.read_json(path)
        doc['flushed_at'] = time.time() - 4000  # idle for over an hour
        spool.write_json_atomic(path, doc)
        self.run_push(force=True)
        self.assertEqual(self.last_payload()['http']['requests_by_status']['2xx'], 5)
        self.fake_process_file(child.pid, started, requests_2xx=6)  # next flush: cumulative
        self.run_push(force=True)
        self.assertEqual(self.last_payload()['http']['requests_by_status']['2xx'], 1)
        self.assertEqual(self.last_payload()['events'], [], 'a live idle worker never "exits"')


@tagged('post_install', '-at_install', 'fivenines')
class TestEvents(FiveninesCase, TransactionCase):

    def test_restart_event(self):
        self.run_push()
        # a previous identity that cannot be ours (Odoo is pid 1 in Docker)
        fake = {'pid': 4194301, 'started_at': 1000.0, 'mode': 'prefork'}
        fm.icp_set(self.icp, fm.P_SERVER, json.dumps(fake))
        self.run_push()
        events = self.last_payload()['events']
        self.assertEqual([e['type'] for e in events], ['server_restart'])
        self.assertEqual(events[0]['previous']['pid'], fake['pid'])
        stored = json.loads(fm.icp_get(self.icp, fm.P_SERVER))
        self.assertNotEqual(stored, fake)
        self.run_push()
        self.assertEqual(self.last_payload()['events'], [])

    def test_workers_changed_event(self):
        import psutil
        self.run_push()
        # a live process that is not this one (whose own file the collector
        # writes); not the parent: Odoo is pid 1 in Docker
        child = subprocess.Popen(['sleep', '60'])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        parent = psutil.Process(child.pid)
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

    def test_setup_cron_runs_forever(self):
        # Value: protects=_setup_cron (run by ir_cron.xml on every install/upgrade) restores numbercall=-1, doall=False on Odoo 16/17; fails_when=_setup_cron gutted or field check inverted, cron runs once; why_new=test_own_cron_excluded_and_repeating checks the installed state only; seam=none; no_claim=Odoo 18+ (no such fields: only active is asserted)
        cron = self.env.ref('fivenines_monitoring.ir_cron_fivenines_push')
        broken = {k: v for k, v in (('numbercall', 1), ('doall', True)) if k in cron._fields}
        if broken:
            cron.write(broken)  # the defaults a plain XML record gets on 16/17
        self.monitor._setup_cron()
        self.assertTrue(cron.active)
        if 'numbercall' in cron._fields:
            self.assertEqual(cron.numbercall, -1)
        if 'doall' in cron._fields:
            self.assertFalse(cron.doall)

    def test_cron_record_is_noupdate(self):
        # Value: protects=a module upgrade does not re-activate a cron deactivated by neutralization or an admin; fails_when=the cron record is not in a noupdate block; why_new=red-team RT8; seam=none; no_claim=a real -u upgrade
        data = self.env['ir.model.data'].sudo().search(
            [('module', '=', 'fivenines_monitoring'), ('name', '=', 'ir_cron_fivenines_push')])
        self.assertTrue(data.noupdate)

    def test_running_stuck_and_unknown_crons(self):
        # Value: protects=locked overdue jobs are running/stuck by lateness, and a failed lock probe gives null counts; fails_when=state thresholds or the None branch break; why_new=testing finding T5 (only late was tested); seam=none; no_claim=a real running cron (probe patched)
        Cron = self.env['ir.cron'].sudo()

        def job(name, minutes_late):
            return Cron.create({
                'name': name, 'model_id': self.env.ref('base.model_res_partner').id,
                'state': 'code', 'code': 'pass', 'interval_number': 1, 'interval_type': 'days',
                'nextcall': fields.Datetime.now() - timedelta(minutes=minutes_late)})

        running, stuck = job('fivenines test running', 10), job('fivenines test stuck', 40)
        M = self.registry['fivenines.monitor']
        with patch.object(M, '_fn_locked_crons', return_value={running.id, stuck.id}):
            b = self.monitor._fn_collect_crons()
        states = {j['id']: j['state'] for j in b['jobs']}
        self.assertEqual((states[running.id], states[stuck.id]), ('running', 'stuck'))
        self.assertGreaterEqual(b['running_count'], 2)
        self.assertGreaterEqual(b['stuck_count'], 1)
        with patch.object(M, '_fn_locked_crons', return_value=None):
            b = self.monitor._fn_collect_crons()
        self.assertIsNone(b['late_count'])
        self.assertIsNone(b['running_count'])
        self.assertGreaterEqual(b['overdue_count'], 2)

    def test_database_block(self):
        block = self.monitor._fn_collect_database()
        self.assertGreater(block['size_bytes'], 0)
        self.assertGreaterEqual(block['connections']['total'], 1)
        self.assertGreater(block['server_max_connections'], 0)


@tagged('post_install', '-at_install', 'fivenines')
class TestSettings(FiveninesCase, TransactionCase):

    def test_settings_roundtrip_and_buttons(self):
        fm.icp_set(self.icp, fm.P_KEY, False)
        settings = self.env['res.config.settings'].create({
            'fivenines_enrollment_key': self.key,
            'fivenines_api_url': self.stub.url,
        })
        self.assertEqual(settings.fivenines_key_source, 'Settings (this database)')
        action = settings.action_fivenines_push_now()
        self.assertEqual(action['tag'], 'display_notification')
        self.assertEqual(action['params']['type'], 'success', action)
        self.assertIsNone(fm.icp_get(self.icp, fm.P_KEY), 'the key is used once')
        fresh = self.env['res.config.settings'].create({})
        self.assertFalse(fresh.fivenines_enrollment_key)
        self.assertTrue(fresh.fivenines_state.startswith('Enrolled'), fresh.fivenines_state)
        self.assertTrue(fresh.fivenines_last_push)
        self.assertTrue(fresh.fivenines_send_error_messages, 'error messages are on by default')
        self.assertEqual(fresh.fivenines_instance_id, fm.icp_get(self.icp, fm.P_INSTANCE))
        action = fresh.action_fivenines_reenroll()
        self.assertEqual(action['params']['type'], 'warning', action)  # no key: nothing forgotten
        again = self.env['res.config.settings'].create({'fivenines_enrollment_key': self.key})
        action = again.action_fivenines_reenroll()
        self.assertEqual(action['params']['type'], 'success', action)
        self.assertEqual(len(self.stub_requests('enroll')), 2)

    def test_notifications_for_local_and_conflict_outcomes(self):
        # Value: protects=Send now reports local errors and a successful conflict re-enroll as such, and never echoes server text; fails_when=every unknown outcome reads as a red 'Fivenines answered'; why_new=maintainability finding M1 + decision D4; seam=none; no_claim=web client rendering
        S = self.env['res.config.settings']
        a = S._fivenines_notify({'result': 'conflict', 'status': 409, 'enroll': 'enrolled'})
        self.assertEqual(a['params']['type'], 'success')
        a = S._fivenines_notify({'result': 'conflict', 'status': 409, 'enroll': 'enrolled', 'state': 'pending'})
        self.assertEqual(a['params']['type'], 'warning')
        a = S._fivenines_notify({'result': 'pending', 'name': 'Copy of Prod (staging)'})
        self.assertIn('Copy of Prod (staging)', a['params']['message'])
        a = S._fivenines_notify({'result': 'config_error', 'message': 'the Fivenines API URL must use https'})
        self.assertNotIn('Fivenines answered', a['params']['message'])
        a = S._fivenines_notify({'result': 'push_failed', 'status': 503, 'kind': 'retry',
                                 'message': '<script>evil</script>'})
        self.assertNotIn('evil', a['params']['message'])

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


@tagged('post_install', '-at_install', 'fivenines')
class TestSettingsUi(FiveninesCase, HttpCase):
    """The standalone settings form renders in the web client of 16-20 and
    "Send now" pushes. Skipped where Chrome is not installed."""

    def test_settings_form_send_now(self):
        action = self.env.ref('fivenines_monitoring.action_fivenines_settings')
        code = """
            const start = Date.now();
            (function check() {
                const key = document.querySelector('[name="fivenines_enrollment_key"]');
                const state = document.querySelector('[name="fivenines_state"]');
                const button = document.querySelector('button[name="action_fivenines_push_now"]');
                if (key && state && button) {
                    button.click();
                    (function notified() {
                        const n = document.querySelector('.o_notification');
                        if (n && n.textContent.includes('Metrics sent to Fivenines')) {
                            console.log('test successful');
                        } else if (Date.now() - start > 40000) {
                            console.error('no success notification: ' + (n ? n.textContent : 'none'));
                        } else {
                            setTimeout(notified, 200);
                        }
                    })();
                } else if (Date.now() - start > 30000) {
                    console.error('Fivenines settings form not rendered');
                } else {
                    setTimeout(check, 250);
                }
            })();
        """
        Settings = self.registry['res.config.settings']
        notify = Settings._fivenines_notify

        def no_reload(self_, outcome):
            # the real action reloads the page after the notification, which
            # would end this script before it sees the notification
            action = notify(self_, outcome)
            action['params'].pop('next', None)
            return action

        with patch.object(Settings, '_fivenines_notify', no_reload):
            try:
                self.browser_js('/web#action=%d' % action.id, code, login='admin', timeout=60)
            except Exception as e:  # noqa: BLE001
                # Odoo 16's test browser teardown calls Storage.clearDataForOrigin
                # with a scheme-less origin, which current Chrome rejects. The
                # push assertion below still checks the click did its job.
                if not (release.version_info[0] == 16 and 'is not a valid URL' in str(e)):
                    raise
        deadline = time.time() + 20
        while time.time() < deadline and not self.stub.state.pushes:
            time.sleep(0.25)
        self.assertTrue(self.stub.state.pushes, 'the Send now button did not push')
        self.assertEqual(self.stub.state.pushes[-1]['payload']['instance']['database'], self.env.cr.dbname)
