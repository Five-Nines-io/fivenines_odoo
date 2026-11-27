# Part of Fivenines Monitoring. License LGPL-3.
"""Pure-Python parts: stats maths, log handler, spool files, cgroup parsing, client."""

import json
import logging
import os
import shutil
import tempfile
import threading
import time

from unittest.mock import patch

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
class TestStatsSamples(BaseCase):
    def _with_sample(self, message, at):
        s = stats.empty_stats()
        stats.record_log(s, 'ERROR', 'fp1', {'logger': 'x'}, {'message': message, 'traceback': None, 'at': at},
                         now=at)
        return s

    def test_merge_keeps_the_latest_sample(self):
        # Value: protects=merging process files keeps the newest message whatever the order; fails_when=the comparison is reversed; why_new=review of revision 2 (testing); seam=none; no_claim=none
        old, new = self._with_sample('old', 100.0), self._with_sample('new', 200.0)
        for parts in ((old, new), (new, old)):
            total = stats.empty_stats()
            for part in parts:
                stats.merge_into(total, part)
            entry = total['logs']['fingerprints']['fp1']
            self.assertEqual((entry['last_message'], entry['count'], entry['last_at']), ('new', 2, 200.0))

    def test_baseline_keeps_counts_only(self):
        # Value: protects=acknowledged baselines in state.json carry no error texts (delta reads counts only); fails_when=state.json grows by every group's texts on every run; why_new=review of revision 2 (red team, adversarial); seam=none; no_claim=disk usage
        snap = self._with_sample('boom with a value', 100.0)
        base = stats.baseline_of(snap)
        self.assertNotIn('last_message', base['logs']['fingerprints']['fp1'])
        self.assertEqual(snap['logs']['fingerprints']['fp1']['last_message'], 'boom with a value')
        stats.record_log(snap, 'ERROR', 'fp1', {'logger': 'x'}, now=101.0)
        self.assertEqual(stats.delta(snap, base)['logs']['fingerprints']['fp1']['count'], 1)

    def test_payload_text_budget(self):
        # Value: protects=one push carries at most MAX_TEXT_TOTAL chars of messages and tracebacks, given to the biggest groups first; fails_when=many long tracebacks push the body past the server's 2 MB cap (413 forever); why_new=review of revision 2 (red team); seam=none; no_claim=JSON escaping overhead
        s = stats.empty_stats()
        for i in range(50):
            for _n in range(50 - i):
                stats.record_log(s, 'ERROR', 'fp%d' % i, {'logger': 'x'},
                                 {'message': 'm' * 2000, 'traceback': 't' * 8000, 'at': 1.0}, now=1.0)
        items = stats.logs_payload(s)['fingerprints']
        sizes = [len(i['last_message'] or '') + len(i['last_traceback'] or '') for i in items]
        self.assertLessEqual(sum(sizes), stats.MAX_TEXT_TOTAL)
        self.assertEqual(items[0]['fingerprint'], 'fp0')
        self.assertEqual(sizes[0], 10000)
        self.assertIsNone(items[-1]['last_message'])
        self.assertIsNotNone(items[-1]['last_seen_at'])


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

    def test_odoo_20_access_line(self):
        # Odoo 20.0's own HTTP server logs through `odoo.http.server` with the
        # status and timings as record attributes (odoo/http/server_log.py)
        def access(status, level=logging.INFO):
            record = logging.LogRecord('odoo.http.server', level, __file__, 1,
                                       '127.0.0.1 - - "GET /web HTTP/1.1" %d' % status, (), None)
            record.http_response_status = status
            record.query_count, record.query_time, record.remaining_time = 7, 0.010, 0.030
            return record
        _Thread.run('db_a', lambda: (self.handler.emit(access(200)), self.handler.emit(access(502)),
                                     self.handler.emit(access(200, logging.DEBUG))))  # [REQ]/[RES]
        no_status = logging.LogRecord('odoo.http.server', logging.INFO, __file__, 1, 'x', (), None)
        no_status.http_response_status = '-'  # no response was sent
        self.assertFalse(fn_collector.is_request_record(no_status))
        snap = self.collector.snapshot('db_a')
        self.assertEqual((snap['http']['status']['2xx'], snap['http']['status']['5xx']), (1, 1))
        self.assertEqual(snap['http']['sql_queries'], 14)
        self.assertAlmostEqual(snap['http']['latency_sum_ms'], 80.0, places=3)
        self.assertEqual(snap['http']['perf_missing'], 0)

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
        # the grouping key never carries values; the latest occurrence's message
        # and traceback do, by design (#6), and the cron drops them when off
        keys = json.dumps([{k: e[k] for k in ('message_template', 'location', 'exception_origin')}
                           for e in fps.values()])
        self.assertNotIn('S0001', keys)
        self.assertNotIn('secret customer value', keys)
        # sampled at most every 10 s per group: the second order, a moment later, keeps the first sample
        self.assertEqual(by_template['Order %s failed']['last_message'], 'Order S0001 failed')
        self.assertIn('secret customer value', by_template['Boom %s']['last_traceback'])

    def test_preformatted_messages_are_masked(self):
        # Value: protects=messages formatted before logging (f-string, str(e)) leave the instance with values masked, and variants share one fingerprint; fails_when=record.msg is sent verbatim when there are no args; why_new=red-team RT4 (customer data in templates); seam=none; no_claim=every PII shape (regex masks)
        def emit(msg, args=None):
            self.handler.emit(logging.LogRecord('odoo.sql_db', logging.ERROR, '/x/odoo/sql_db.py', 10, msg, args, None))

        _Thread.run('db_a', lambda: (
            emit('duplicate key value: Key (email)=(john@example.com) already exists, id 42'),
            emit('duplicate key value: Key (email)=(mary@example.com) already exists, id 77'),
            emit('Order %s failed', ('S0001',))))
        fps = self.collector.snapshot('db_a')['logs']['fingerprints']
        text = json.dumps([e['message_template'] for e in fps.values()])  # the grouping key
        for value in ('john@', 'mary@', '42', '77'):
            self.assertNotIn(value, text)
        self.assertEqual(len(fps), 2, 'the two pre-formatted variants share one fingerprint')
        templates = sorted(e['message_template'] for e in fps.values())
        self.assertIn('Order %s failed', templates)  # a real template is kept as is

    def test_masking_is_bounded_on_huge_tokens(self):
        # Value: protects=one ERROR log carrying a huge token (base64, JWT, hex dump) cannot stall logging: the masks only ever see a bounded prefix; fails_when=mask_values runs over the whole message (quadratic: 50k chars ~5 s, 1 MB ~35 min, GIL and handler lock held); why_new=adversarial + performance review (pass 2); seam=none; no_claim=regex complexity on the prefix itself
        # Regression proof - fails at HEAD: yes (masks fed 1,080,010 chars; an in-thread deadline cannot even fire, re holds the GIL) - passes at base: unavailable (ecosystem) - passes after fix: yes
        token = ('a1b2c3.d4e5_' * 90000)  # ~1 MB, no '@', no space
        record = logging.LogRecord('odoo.http', logging.ERROR, '/x/odoo/http.py', 1, 'bad token ' + token, None, None)
        seen = []
        real = fn_collector.mask_values

        regexes_saw = []
        real_sub = fn_collector._MASKS[0][0].sub

        def spy(text):
            seen.append(len(text))
            return real(text)

        class Spy:  # what the first mask regex actually scans
            def sub(self, repl, text):
                regexes_saw.append(len(text))
                return real_sub(repl, text[:2100])  # bounds a red run

        masks = ((Spy(), fn_collector._MASKS[0][1]),) + fn_collector._MASKS[1:]
        with patch.object(fn_collector, 'mask_values', spy), patch.object(fn_collector, '_MASKS', masks):
            fp, info = fn_collector.log_fingerprint(record)
        self.assertLessEqual(max(regexes_saw), 2000)
        self.assertTrue(seen)
        self.assertLessEqual(len(info['message_template']), 300)
        # values cut at the bound never escape their mask (fix-check and adversarial repros)
        mask = fn_collector.mask_values
        pad = 'customer Jane Doe ' * 150
        cases = {
            'Bad payload "' + 'customer Jane ' * 300 + '" end': 'Bad payload  [cut]',
            "Webhook failed: '" + 'x' * 3000 + "'": 'Webhook failed:  [cut]',
            "Can't import \"O'Brien " + pad: 'Can [cut]',
            "Partner doesn't match: Key (name)=(O'Brien " + pad: 'Partner doesn [cut]',
            'Import failed: can\'t save "Jane Doe lives at Elm street, it\'s her ' + pad + '" end': 'Import failed: can [cut]',
            'Partner match: Key (name)=(' + pad: 'Partner match: Key (name) [cut]',
        }
        for message, expected in cases.items():
            self.assertEqual(mask(message), expected)
            self.assertNotIn('Jane', mask(message))
        cut = mask('order ' + 'x' * 1983 + ' to jane.doe@corp.com and more ' + 'y' * 50)
        self.assertNotIn('jane', cut)
        self.assertEqual(mask('a@b.com+c@d.com'), '<email><email>')
        self.assertEqual(mask('step 1.https://h/s?k=1'), 'step N.<url>')
        # a short message keeps its text after an apostrophe (closed pairs only)
        self.assertEqual(mask("Record doesn't exist or has been deleted. (Record: res.partner(42,), User: 7)"),
                         "Record doesn't exist or has been deleted. (Record: res.partner(N,), User: N)")

    def test_credentials_masked_in_messages_and_tracebacks(self):
        # Value: protects=passwords, Authorization values, API keys, tokens in URLs/DSNs, JWTs and long hex secrets are masked in every text that leaves the instance, in bounded time; fails_when=a mask is removed or goes quadratic; why_new=#6 (messages on by default); seam=none; no_claim=every credential shape (deny-list)
        m = fn_collector.mask_credentials
        cases = {
            'connect postgres://odoo:S3cret!@db:5432/prod failed': 'connect postgres://***:***@db:5432/prod failed',
            'Authorization: Bearer abcdef0123456789xyz': 'Authorization: Bearer ***',
            'POST /api?token=abc123&x=1': 'POST /api?token=***&x=1',
            '{"api_key": "sk_live_123456", "password": "hunter2"}': '{"api_key": "***", "password": "***"}',
            'jwt eyJhbGciOi.eyJzdWIiOi.sig123': 'jwt <jwt>',
            'key 0123456789abcdef0123456789abcdef01234567': 'key <hex>',
        }
        for text, expected in cases.items():
            self.assertEqual(m(text), expected)
        try:
            raise ValueError('cannot reach smtp://mailer:pw123@mail.example.com')
        except ValueError:
            import sys
            record = logging.LogRecord('odoo.x', logging.ERROR, __file__, 1, 'Sync of %s failed: password=%s',
                                       ('jane@example.com', 'hunter2'), sys.exc_info())
        sample = fn_collector.error_sample(record)
        self.assertEqual(sample['message'], 'Sync of jane@example.com failed: password=***')
        self.assertIn('smtp://***:***@mail.example.com', sample['traceback'])
        self.assertNotIn('pw123', sample['traceback'])
        long_record = logging.LogRecord('odoo.x', logging.ERROR, __file__, 1, 'x ' * 5000, None, None)
        self.assertLessEqual(len(fn_collector.error_sample(long_record)['message']), 2010)
        for text in ('a' * 8000, 'password=' * 1000, ':' * 8000, 'x://' + 'a' * 7990):
            m(text)  # bounded: each runs in well under a second (quadratic patterns would not)

    def test_cut_never_separates_a_secret_from_its_name(self):
        # Value: protects=a traceback cut at 8000 chars from the end never leaves a credential's value bare because the cut dropped its name; fails_when=masking runs after the cut again; why_new=review of revision 2 (security, adversarial: verified leak); seam=none; no_claim=every credential shape
        for shift in range(0, 40, 3):
            tb = 'Traceback\n' + 'a' * shift + ' password: hunter2secret ' + 'y ' * 3990
            record = logging.LogRecord('odoo.x', logging.ERROR, __file__, 1, 'boom', None, None)
            record.exc_text = tb
            sample = fn_collector.error_sample(record)
            self.assertNotIn('hunter2secret', sample['traceback'])
            self.assertLessEqual(len(sample['traceback']), fn_collector.MAX_TRACEBACK + 10)
            self.assertTrue(sample['traceback'].startswith('[cut] '))

    def test_mask_window_never_splits_a_token(self):
        # Value: protects=the masking window opens on a whitespace, so a long hex secret at its edge is masked whole, never sent as a fragment, even when masks shrink the window; fails_when=the window is cut at a raw offset; why_new=review pass 2 (security); seam=none; no_claim=none
        secret = 'ab' * 40  # 80 hex chars
        token = 'cd' * 20 + ' '  # masked to "<hex> ": the window shrinks 7x
        for keep, limit in (('head', 2000), ('tail', 8000)):
            size = limit + fn_collector.MASK_MARGIN
            for shift in range(1, 79, 6):
                if keep == 'head':
                    pad = (token * (size // len(token) + 1))[:size - shift]
                    text = pad.rstrip() + ' ' + secret + ' end'
                else:
                    pad = (token * (size // len(token) + 1))[:size - shift]
                    text = 'start ' + secret + ' ' + pad.lstrip()
                out = fn_collector._masked_bounded(text, limit, keep)
                self.assertNotIn('abab', out, (keep, shift))

    def test_long_last_line_is_kept_and_marked_cut(self):
        # Value: protects=a traceback whose last line is very long keeps its tail and the "[cut] " marker; fails_when=the window opens after a far newline and empties or silently truncates the traceback; why_new=review fix-check (red team); seam=none; no_claim=none
        # a long last line of words, then a short line: the tail is kept and marked
        tb = 'Traceback\nValueError: ' + 'w ' * 8000 + '\nDuring handling: short'
        out = fn_collector._masked_bounded(tb, fn_collector.MAX_TRACEBACK, 'tail')
        self.assertTrue(out.startswith('[cut] '), out[:40])
        self.assertTrue(out.endswith('During handling: short'))
        self.assertGreater(len(out), 7000)
        # one unbroken 13,000-char token cannot be cut safely: dropped, but marked
        out = fn_collector._masked_bounded('Traceback\nValueError: ' + 'x' * 13000 + '\n',
                                           fn_collector.MAX_TRACEBACK, 'tail')
        self.assertTrue(out.startswith('[cut] '))
        short = fn_collector._masked_bounded('a ' * 1500, fn_collector.MAX_MESSAGE, 'head')
        self.assertTrue(short.endswith('[cut]'))

    def test_error_sample_is_built_at_most_every_10_seconds(self):
        # Value: protects=an error storm does not pay the masking cost (~1 ms, under the logging lock) per record: one sample per group per SAMPLE_EVERY, while every occurrence is still counted; fails_when=error_sample runs for every record again; why_new=review of revision 2 (performance, adversarial); seam=patched error_sample; no_claim=wall-clock timings
        calls = []
        real = fn_collector.error_sample
        with patch.object(fn_collector, 'error_sample', lambda r: calls.append(1) or real(r)):
            def storm():
                for _i in range(50):
                    self.handler.emit(logging.LogRecord('odoo.x', logging.ERROR, __file__, 7,
                                                        'Order %s failed', ('S1',), None))
            _Thread.run('db_a', storm)
        snap = self.collector.snapshot('db_a')
        (entry,) = snap['logs']['fingerprints'].values()
        self.assertEqual(entry['count'], 50)
        self.assertEqual(len(calls), 1)
        self.assertEqual(entry['last_message'], 'Order S1 failed')

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

    def test_classify_pending_and_ignored(self):
        # Value: protects=pending needs the contract's marker and its retry_after is bounded (junk and inf included); a 410 is final only with code "ignored", and a bare 202 is not an acknowledgement; fails_when=a CDN's 410 or a proxy's 202 puts every database in a final or data-dropping state, or retry_after=inf crashes the run; why_new=review of revision 2 (red team, adversarial, testing); seam=none; no_claim=real proxies
        c = fn_client.classify
        self.assertEqual(c(202, {'state': 'pending'}).kind, fn_client.PENDING)
        self.assertEqual(c(200, {'status': 'pending'}).kind, fn_client.PENDING)
        self.assertEqual(c(202, {'state': 'pending'}).retry_after, 900)
        self.assertEqual(c(202, {'state': 'pending', 'retry_after': 5}).retry_after, 300)
        self.assertEqual(c(202, {'state': 'pending', 'retry_after': 10 ** 9}).retry_after, 21600)
        for junk in ('x', 'inf', float('inf'), '1e999', None):
            self.assertEqual(c(202, {'state': 'pending', 'retry_after': junk}).retry_after, 900)
        self.assertEqual(c(202, None).kind, fn_client.RETRY)
        self.assertEqual(c(202, {'status': 'ok'}).kind, fn_client.RETRY)
        self.assertEqual(c(410, {'status': 'error', 'code': 'ignored'}).kind, fn_client.IGNORED)
        self.assertEqual(c(410, None).kind, fn_client.RETRY)
        self.assertEqual(c(410, {'message': 'Gone'}).kind, fn_client.RETRY)

        class _Resp:
            headers = {'Retry-After': 'inf'}
        self.assertIsNone(fn_client._retry_after(_Resp()))

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
