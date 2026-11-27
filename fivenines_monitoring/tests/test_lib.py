# Part of Fivenines Monitoring. License LGPL-3.
"""Pure-Python parts: stats maths, log handler, spool files, cgroup parsing, client."""

import json
import logging
import os
import shutil
import tempfile
import threading
import time

from odoo.tests.common import BaseCase, tagged

from ..lib import client as fn_client
from ..lib import collector as fn_collector
from ..lib import spool, stats
from ..lib import system as fn_system


def _request_record(code, perf_info='12 0.040 0.060', colored=False):
    msg = '127.0.0.1 - - [26/Nov/2026 10:00:00] "%s" %s %s\n'
    if colored:
        code = '\x1b[1m%s\x1b[0m' % code
    record = logging.LogRecord('werkzeug', logging.INFO, __file__, 1, msg,
                               ('GET /web HTTP/1.1', str(code), '-'), None)
    record.perf_info = perf_info
    return record


class _Thread:
    """Run `fn` in a thread whose dbname is `dbname` (like an Odoo request)."""

    @staticmethod
    def run(dbname, fn):
        def target():
            threading.current_thread().dbname = dbname
            fn()
        t = threading.Thread(target=target)
        t.start()
        t.join()


@tagged('post_install', '-at_install', 'fivenines')
class TestStats(BaseCase):

    def test_status_class(self):
        self.assertEqual(stats.status_class(200), '2xx')
        self.assertEqual(stats.status_class('503'), '5xx')
        self.assertEqual(stats.status_class(None), 'other')
        self.assertEqual(stats.status_class('-'), 'other')

    def test_percentile_empty_is_unknown(self):
        self.assertIsNone(stats.percentile([0] * 14, 0.5))

    def test_percentile_interpolates(self):
        buckets = [0] * 14
        buckets[stats.bucket_index(80)] = 100  # all in the 50-100 ms bucket
        self.assertEqual(stats.percentile(buckets, 0.5), 75.0)
        self.assertEqual(stats.percentile(buckets, 1.0), 100.0)

    def test_delta_and_merge(self):
        a = stats.empty_stats()
        stats.record_request(a, 200, 50.0, 10, 5.0)
        base = json.loads(json.dumps(a))
        stats.record_request(a, 500, 300.0, 20, 15.0)
        stats.record_log(a, 'ERROR', 'fp1', {'logger': 'x'})
        d = stats.delta(a, base)
        self.assertEqual(d['http']['status']['5xx'], 1)
        self.assertEqual(d['http']['status']['2xx'], 0)
        self.assertEqual(d['http']['sql_queries'], 20)
        self.assertEqual(d['logs']['fingerprints']['fp1']['count'], 1)
        # a counter going backwards = another process life
        self.assertIsNone(stats.delta(base, a))
        total = stats.merge_into(stats.empty_stats(), d)
        stats.merge_into(total, d)
        self.assertEqual(total['http']['status']['5xx'], 2)
        self.assertEqual(total['logs']['fingerprints']['fp1']['count'], 2)

    def test_http_payload_nulls(self):
        self.assertIsNone(stats.http_payload(stats.empty_stats(), 60, capture_enabled=False))
        p = stats.http_payload(stats.empty_stats(), 60)
        self.assertEqual(p['requests_total'], 0)
        self.assertIsNone(p['latency_ms']['p95'])  # unknown, never 0
        self.assertIsNone(p['sql_queries_per_request'])
        self.assertIsNone(stats.http_payload(stats.empty_stats(), 0)['requests_per_minute'])

    def test_fingerprint_cap(self):
        s = stats.empty_stats()
        for i in range(stats.MAX_FINGERPRINTS + 5):
            stats.record_log(s, 'ERROR', 'fp%d' % i, {})
        self.assertEqual(len(s['logs']['fingerprints']), stats.MAX_FINGERPRINTS)
        self.assertEqual(s['logs']['overflow'], 5)
        self.assertEqual(s['logs']['levels']['ERROR'], stats.MAX_FINGERPRINTS + 5)
        self.assertTrue(stats.logs_payload(s)['fingerprints_truncated'])


@tagged('post_install', '-at_install', 'fivenines')
class TestCollector(BaseCase):

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.collector = fn_collector.Collector()
        self.handler = fn_collector.FiveninesHandler(self.collector)
        self.dir = os.path.join(self.tmp, 'spool', 'db_a-x')
        self.collector.register_db('db_a', self.dir)

    def test_parse_perf_info(self):
        self.assertEqual(fn_collector.parse_perf_info('12 0.040 0.060'), (12, 0.04, 0.06))
        # Odoo 18+ with a read replica adds the cursor mode
        self.assertEqual(fn_collector.parse_perf_info('3 0.010 0.020 ro'), (3, 0.01, 0.02))
        colored = '\x1b[1;33;49m120\x1b[0m 0.040 \x1b[1;31;49m6.000\x1b[0m'
        self.assertEqual(fn_collector.parse_perf_info(colored), (120, 0.04, 6.0))
        self.assertIsNone(fn_collector.parse_perf_info('- - -'))
        self.assertIsNone(fn_collector.parse_perf_info(''))

    def test_requests_counted_for_own_db_only(self):
        _Thread.run('db_a', lambda: self.handler.emit(_request_record(200)))
        _Thread.run('db_a', lambda: self.handler.emit(_request_record(404, colored=True)))
        _Thread.run('db_b', lambda: self.handler.emit(_request_record(200)))  # other db
        _Thread.run(None, lambda: self.handler.emit(_request_record(200)))    # no db
        snap = self.collector.snapshot('db_a')
        self.assertEqual(snap['http']['status']['2xx'], 1)
        self.assertEqual(snap['http']['status']['4xx'], 1)
        self.assertEqual(snap['http']['sql_queries'], 24)
        self.assertAlmostEqual(snap['http']['latency_sum_ms'], 200.0, places=3)
        self.assertIsNone(self.collector.snapshot('db_b'))

    def test_preformatted_werkzeug_1_line(self):
        # werkzeug 1.0 formats the line itself: no record.args
        msg = '127.0.0.1 - - [26/Nov/2026 22:47:49] "GET /web/login HTTP/1.1" 503 -\n'
        record = logging.LogRecord('werkzeug', logging.INFO, __file__, 1, msg, None, None)
        record.perf_info = '4 0.001 0.002'
        self.assertTrue(fn_collector.is_request_record(record))
        _Thread.run('db_a', lambda: self.handler.emit(record))
        startup = logging.LogRecord('werkzeug', logging.INFO, __file__, 1, ' * Running on http://x/', None, None)
        self.assertFalse(fn_collector.is_request_record(startup))
        snap = self.collector.snapshot('db_a')
        self.assertEqual(snap['http']['status']['5xx'], 1)
        self.assertEqual(snap['http']['sql_queries'], 4)

    def test_request_without_perf_info(self):
        _Thread.run('db_a', lambda: self.handler.emit(_request_record(200, perf_info='- - -')))
        snap = self.collector.snapshot('db_a')
        self.assertEqual(snap['http']['status']['2xx'], 1)
        self.assertEqual(snap['http']['perf_missing'], 1)

    def test_error_fingerprints(self):
        def log(msg, args, exc=False):
            exc_info = None
            if exc:
                try:
                    raise ValueError('secret customer value %s' % args)
                except ValueError:
                    import sys
                    exc_info = sys.exc_info()
            record = logging.LogRecord('odoo.addons.sale', logging.ERROR, '/x/odoo/addons/sale/models/sale.py',
                                       42, msg, args, exc_info)
            self.handler.emit(record)

        _Thread.run('db_a', lambda: (log('Order %s failed', ('S0001',)), log('Order %s failed', ('S0002',)),
                                     log('Boom %s', ('x',), exc=True)))
        snap = self.collector.snapshot('db_a')
        fps = snap['logs']['fingerprints']
        self.assertEqual(snap['logs']['levels']['ERROR'], 3)
        self.assertEqual(len(fps), 2)  # same template = same fingerprint
        by_template = {e['message_template']: e for e in fps.values()}
        self.assertEqual(by_template['Order %s failed']['count'], 2)
        self.assertEqual(by_template['Boom %s']['exception_type'], 'ValueError')
        self.assertIn('test_lib.py', by_template['Boom %s']['exception_origin'])
        self.assertNotIn('S0001', json.dumps(fps))
        self.assertNotIn('secret customer value', json.dumps(fps))

    def test_preformatted_messages_are_masked(self):
        # Value: protects=messages formatted before logging (f-string, str(e)) leave the instance with values masked, and variants share one fingerprint; fails_when=record.msg is sent verbatim when there are no args; why_new=red-team RT4 (customer data in templates); seam=none; no_claim=every PII shape (regex masks)
        def emit(msg, args=None):
            self.handler.emit(logging.LogRecord('odoo.sql_db', logging.ERROR, '/x/odoo/sql_db.py', 10, msg, args, None))

        _Thread.run('db_a', lambda: (
            emit('duplicate key value: Key (email)=(john@example.com) already exists, id 42'),
            emit('duplicate key value: Key (email)=(mary@example.com) already exists, id 77'),
            emit('Order %s failed', ('S0001',))))
        fps = self.collector.snapshot('db_a')['logs']['fingerprints']
        text = json.dumps(fps)
        for value in ('john@', 'mary@', '42', '77'):
            self.assertNotIn(value, text)
        self.assertEqual(len(fps), 2, 'the two pre-formatted variants share one fingerprint')
        templates = sorted(e['message_template'] for e in fps.values())
        self.assertIn('Order %s failed', templates)  # a real template is kept as is

    def test_prefork_master_is_ignored(self):
        # Value: protects=the prefork master never counts nor starts the flusher thread before forking; fails_when=ignore_pid is not honoured; why_new=red-team RT12; seam=none; no_claim=a real fork
        self.collector.ignore_pid = os.getpid()
        _Thread.run('db_a', lambda: self.handler.emit(_request_record(200)))
        self.assertIsNone(self.collector.snapshot('db_a'))
        self.assertIsNone(self.collector._thread)

    def test_flush_writes_atomically(self):
        _Thread.run('db_a', lambda: self.handler.emit(_request_record(200)))
        self.collector.flush()
        files = spool.list_process_files(self.dir)
        self.assertEqual(len(files), 1)
        key, path, pid, start = files[0]
        self.assertEqual(pid, os.getpid())
        doc = spool.read_json(path)
        self.assertEqual(doc['stats']['http']['status']['2xx'], 1)
        self.assertFalse([n for n in os.listdir(self.dir) if n.startswith('.tmp-')])
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)

    def test_force_info_keeps_output_quiet(self):
        name = 'fivenines.test.quiet.%s' % id(self)
        target = logging.getLogger(name)
        target.setLevel(logging.WARNING)
        target.propagate = False
        seen_by_other, seen_by_us = [], []

        class Capture(logging.Handler):
            def __init__(self, sink):
                super().__init__()
                self.sink = sink

            def emit(self, record):
                self.sink.append(record)

        other = Capture(seen_by_other)
        target.addHandler(other)
        self.collector.handler = Capture(seen_by_us)
        target.addHandler(self.collector.handler)
        self.assertEqual(self.collector.force_info(name), 'forced')
        self.assertEqual(self.collector.force_info(name), 'native')  # idempotent
        target.info('an access line')
        target.warning('a warning')
        self.assertEqual([r.getMessage() for r in seen_by_us], ['an access line', 'a warning'])
        self.assertEqual([r.getMessage() for r in seen_by_other], ['a warning'])

    def test_handler_never_raises(self):
        record = _request_record(200)
        record.args = None  # malformed
        _Thread.run('db_a', lambda: self.handler.emit(record))
        broken = logging.LogRecord('x', logging.ERROR, None, None, object(), None, None)
        _Thread.run('db_a', lambda: self.handler.emit(broken))


@tagged('post_install', '-at_install', 'fivenines')
class TestSpool(BaseCase):

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_db_dir_is_unique_per_target(self):
        a = spool.db_dir('odoo', 'localhost', 5432, self.tmp)
        b = spool.db_dir('odoo', 'otherhost', 5432, self.tmp)
        self.assertNotEqual(a, b)
        self.assertTrue(os.path.basename(a).startswith('odoo-'))
        self.assertIn('fivenines-%d' % os.getuid(), spool.base_dir())
        self.assertNotIn('/', os.path.basename(spool.db_dir('../evil/db', '', '', self.tmp)))

    def test_refuses_symlinked_dir(self):
        real = os.path.join(self.tmp, 'real')
        os.mkdir(real)
        os.symlink(real, os.path.join(self.tmp, 'link'))
        with self.assertRaises(PermissionError):
            spool.ensure_dir(os.path.join(self.tmp, 'link'))

    def test_process_alive_checks_start_time(self):
        import psutil
        me = psutil.Process().create_time()
        self.assertTrue(spool.process_alive(os.getpid(), me))
        self.assertFalse(spool.process_alive(os.getpid(), me - 3600))  # pid reused
        self.assertFalse(spool.process_alive(2 ** 22 + 12345, me))

    def test_state_lock_is_exclusive(self):
        with spool.StateLock(self.tmp) as first:
            self.assertTrue(first.acquired)
            # flock is per open file description: a second open conflicts
            with spool.StateLock(self.tmp) as second:
                self.assertFalse(second.acquired)
        with spool.StateLock(self.tmp) as third:
            self.assertTrue(third.acquired)

    def test_old_temp_files_are_cleaned(self):
        path = os.path.join(self.tmp, '.tmp-abc')
        open(path, 'w').close()
        os.utime(path, (time.time() - 1000, time.time() - 1000))
        spool.list_process_files(self.tmp)
        self.assertFalse(os.path.exists(path))


@tagged('post_install', '-at_install', 'fivenines')
class TestSystem(BaseCase):

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _write(self, rel, content):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_cgroup_v2_limits(self):
        root = os.path.join(self.tmp, 'cg')
        self._write('cg/cgroup.controllers', 'cpu memory pids')
        self._write('cg/cpu.max', '200000 100000')
        self._write('cg/memory.max', '1073741824')
        self._write('cg/memory.current', '536870912')
        self._write('cg/memory.stat', 'anon 1\ninactive_file 134217728\n')
        self._write('cg/cpu.stat', 'usage_usec 5000000\nthrottled_usec 250000\n')
        self._write('cg/pids.current', '12')
        self._write('cg/pids.max', 'max')
        proc = self._write('proc_cgroup', '0::/\n')
        cg = fn_system.read_cgroup(root, proc)
        self.assertEqual(cg['version'], 2)
        self.assertEqual(cg['cpu_limit_cores'], 2.0)
        self.assertEqual(cg['memory_limit_bytes'], 1073741824)
        self.assertFalse(cg['memory_unlimited'])
        self.assertEqual(cg['cpu_usage_seconds'], 5.0)
        self.assertIsNone(cg['pids_limit'])

    def test_cgroup_v2_unlimited_is_null(self):
        root = os.path.join(self.tmp, 'cg')
        self._write('cg/cgroup.controllers', '')
        self._write('cg/system.slice/odoo.service/cpu.max', 'max 100000')
        self._write('cg/system.slice/odoo.service/memory.max', 'max')
        self._write('cg/system.slice/odoo.service/memory.current', '1000')
        proc = self._write('proc_cgroup', '0::/system.slice/odoo.service\n')
        cg = fn_system.read_cgroup(root, proc)
        self.assertIsNone(cg['cpu_limit_cores'])
        self.assertIsNone(cg['memory_limit_bytes'])
        self.assertTrue(cg['memory_unlimited'])
        self.assertEqual(cg['memory_usage_bytes'], 1000)
        self.assertIsNone(cg['cpu_usage_seconds'])  # file missing: unknown

    def test_cgroup_v1(self):
        root = os.path.join(self.tmp, 'cg')
        self._write('cg/memory/memory.limit_in_bytes', str(2 ** 63 - 4096))  # unlimited
        self._write('cg/memory/memory.usage_in_bytes', '4096')
        self._write('cg/cpu,cpuacct/cpu.cfs_quota_us', '50000')
        self._write('cg/cpu,cpuacct/cpu.cfs_period_us', '100000')
        self._write('cg/cpu,cpuacct/cpuacct.usage', '3000000000')
        proc = self._write('proc_cgroup', '4:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n')
        cg = fn_system.read_cgroup(root, proc)
        self.assertEqual(cg['version'], 1)
        self.assertEqual(cg['cpu_limit_cores'], 0.5)
        self.assertIsNone(cg['memory_limit_bytes'])
        self.assertTrue(cg['memory_unlimited'])
        self.assertEqual(cg['cpu_usage_seconds'], 3.0)

    def test_no_cgroup(self):
        self.assertIsNone(fn_system.read_cgroup(os.path.join(self.tmp, 'none'), '/nonexistent'))

    def test_collect_rates_need_two_samples(self):
        block, sample, errors = fn_system.collect(None, self.tmp, os.getpid(), now=1000.0,
                                                  cgroup_root=os.path.join(self.tmp, 'none'))
        self.assertEqual(errors, [])
        self.assertIsNone(block['host']['cpu_usage_percent'])  # first sample: unknown
        self.assertIsNone(block['cgroup'])
        self.assertGreater(block['host']['memory_total_bytes'], 0)
        self.assertGreaterEqual(block['odoo_processes']['count'], 1)
        sum(i * i for i in range(200000))  # burn a little CPU
        block2, _s, _e = fn_system.collect(sample, self.tmp, os.getpid(), now=1060.0,
                                           cgroup_root=os.path.join(self.tmp, 'none'))
        self.assertIsNotNone(block2['host']['cpu_usage_percent'])
        self.assertEqual(block2['sample_interval_seconds'], 60.0)


@tagged('post_install', '-at_install', 'fivenines')
class TestClient(BaseCase):

    def test_check_api_url(self):
        self.assertEqual(fn_client.check_api_url('https://api.fivenines.io/'), 'https://api.fivenines.io')
        self.assertEqual(fn_client.check_api_url('http://127.0.0.1:8899'), 'http://127.0.0.1:8899')
        self.assertEqual(fn_client.check_api_url('http://[::1]:8899'), 'http://[::1]:8899')
        self.assertEqual(fn_client.check_api_url('http://localhost:8899'), 'http://localhost:8899')
        # Value: protects=plain http only to real loopback addresses; fails_when=a DNS name that looks like an IP (127.example.com) gets the exemption; why_new=security finding S1; seam=none; no_claim=DNS resolution
        for name in ('127.example.com', '127.0.0.1.nip.io', 'localhost.example.com'):
            self.assertFalse(fn_client.is_loopback(name), name)
            with self.assertRaises(ValueError):
                fn_client.check_api_url('http://%s' % name)
        with self.assertRaises(ValueError):
            fn_client.check_api_url('http://api.fivenines.io')
        self.assertEqual(fn_client.check_api_url('http://10.0.0.5', allow_insecure=True), 'http://10.0.0.5')
        with self.assertRaises(ValueError):
            fn_client.check_api_url('https://user:pw@api.fivenines.io')
        with self.assertRaises(ValueError):
            fn_client.check_api_url('ftp://x')

    def test_classify(self):
        self.assertEqual(fn_client.classify(200, {'status': 'ok'}).kind, fn_client.OK)
        self.assertEqual(fn_client.classify(401, {'message': 'x'}).kind, fn_client.UNAUTHORIZED)
        self.assertEqual(fn_client.classify(409, None).kind, fn_client.CONFLICT)
        self.assertEqual(fn_client.classify(422, None).kind, fn_client.REJECTED)
        self.assertEqual(fn_client.classify(429, None, 30).retry_after, 30)
        for status in (404, 500, 502, 503, 504):
            self.assertEqual(fn_client.classify(status, None).kind, fn_client.RETRY)
        # Value: protects=403 holds (instance limit), 402 holds, 400/413 are rejected not retried; fails_when=status map edited; why_new=only 401/409/422/429 asserted; seam=none; no_claim=handler effects
        self.assertEqual(fn_client.classify(403, None).kind, fn_client.FORBIDDEN)
        self.assertEqual(fn_client.classify(402, None).kind, fn_client.PAYMENT_REQUIRED)
        for status in (400, 413):
            self.assertEqual(fn_client.classify(status, None).kind, fn_client.REJECTED)

    def test_retry_after_header(self):
        # Value: protects=Retry-After parsed, clamped to [0, MAX_RETRY_AFTER], junk ignored; fails_when=clamp/parse removed so server can stall pushes or crash; why_new=_retry_after untested; seam=none; no_claim=HTTP-date form
        class _Resp:
            def __init__(self, value):
                self.headers = {} if value is None else {'Retry-After': value}
        ra = fn_client._retry_after
        self.assertEqual(ra(_Resp('120')), 120)
        self.assertEqual(ra(_Resp('1.5')), 1)
        self.assertEqual(ra(_Resp('-5')), 0)
        self.assertEqual(ra(_Resp('99999999')), fn_client.MAX_RETRY_AFTER)
        self.assertIsNone(ra(_Resp('Wed, 21 Oct 2015 07:28:00 GMT')))
        self.assertIsNone(ra(_Resp(None)))

    def test_backoff_is_bounded(self):
        delays = [fn_client.backoff_delay(n) for n in range(1, 12)]
        self.assertEqual(delays[:3], [60, 60, 60])
        self.assertEqual(delays[3:6], [120, 240, 480])
        self.assertEqual(max(delays), 900)
