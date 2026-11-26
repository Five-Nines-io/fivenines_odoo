#!/usr/bin/env python3
# Part of Fivenines Monitoring. License LGPL-3.
"""End-to-end check on a real Odoo server (from source), pushing to the stub.

    python3 tools/e2e_local.py --odoo-bin ~/odoo-19.0/odoo-bin --python ~/venv-19/bin/python \
        --addons-path ~/odoo-19.0/addons --port 19069 --stub-port 19899

Scenarios (each waits for real cron pushes, nothing is called directly):
  1. workers=0, one database (A)
  2. workers=2 (prefork), two databases (A and B) on ONE server, no dbfilter:
     each database must report only its own requests
  3. a copy of A (createdb -T, the copy keeps database.uuid and the secret):
     the copy must re-enroll as a new instance
Also records whether Odoo's own duplicate gives the copy a new database.uuid.

Uses throwaway databases (prefix fne2e_<serie>_) and drops them at the end.
Needs a local PostgreSQL the current user can create databases on.
"""

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
STUB = os.path.join(REPO, 'fivenines_monitoring', 'tests', 'stub_server.py')


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def psql(args, db, sql):
    return sh(['psql', '-h', args.db_host, '-U', args.db_user, '-d', db, '-Atc', sql]).strip()


class Run:
    def __init__(self, args):
        self.args = args
        self.tmp = tempfile.mkdtemp(prefix='fne2e-')
        self.key = secrets.token_hex(32)
        self.stub_url = 'http://127.0.0.1:%d' % args.stub_port
        self.serie = None
        self.server = None
        self.report = {'scenarios': {}}

    # -- helpers ---------------------------------------------------------
    def stub_state(self):
        with urllib.request.urlopen(self.stub_url + '/_stub/state', timeout=5) as r:
            return json.load(r)

    def odoo(self, *extra, check=True):
        a = self.args
        cmd = [a.python, a.odoo_bin, '--addons-path=%s,%s' % (a.addons_path, REPO),
               '--db_host=%s' % a.db_host, '--db_user=%s' % a.db_user, *extra]
        return subprocess.run(cmd, check=check, capture_output=True, text=True)

    def write_conf(self, workers, db_filter=None):
        path = os.path.join(self.tmp, 'odoo-%d.conf' % workers)
        lines = [
            '[options]',
            'addons_path = %s,%s' % (self.args.addons_path, REPO),
            'db_host = %s' % self.args.db_host,
            'db_user = %s' % self.args.db_user,
            'http_port = %d' % self.args.port,
            'workers = %d' % workers,
            'max_cron_threads = 1',
            'logfile = %s' % os.path.join(self.tmp, 'odoo-%d.log' % workers),
            'log_level = info',
            # the deployment-config path for the key and the API URL
            'fivenines_enrollment_key = %s' % self.key,
            'fivenines_api_url = %s' % self.stub_url,
        ]
        if db_filter:
            lines.append('dbfilter = %s' % db_filter)
        if workers:
            lines += ['limit_time_cpu = 600', 'limit_time_real = 1200']
        with open(path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        return path

    def start(self, conf, dbs):
        a = self.args
        cmd = [a.python, a.odoo_bin, '-c', conf, '--database=%s' % ','.join(dbs)]
        self.server = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
        # a bare TCP connect: an HTTP probe would be counted as a request
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                socket.create_connection(('127.0.0.1', a.port), timeout=2).close()
                time.sleep(2)
                return
            except OSError:
                time.sleep(1)
        raise RuntimeError('Odoo did not start')

    def stop(self):
        if self.server:
            os.killpg(self.server.pid, signal.SIGTERM)
            try:
                self.server.wait(30)
            except subprocess.TimeoutExpired:
                os.killpg(self.server.pid, signal.SIGKILL)
            self.server = None
            time.sleep(1)

    def select_db(self, db):
        """Bind a cookie jar to `db`. Done BEFORE the measured window: on a
        multi-database server this first request can be answered before a
        database is attached (redirect), so it cannot be attributed."""
        jar = os.path.join(self.tmp, 'jar-%s' % db)
        base = 'http://127.0.0.1:%d' % self.args.port
        sh(['curl', '-s', '-o', '/dev/null', '-c', jar, '-b', jar, '%s/web/login?db=%s' % (base, db)])

    def traffic(self, db, ok, missing):
        """`ok` GET /web/login and `missing` 404s against database `db`."""
        jar = os.path.join(self.tmp, 'jar-%s' % db)
        base = 'http://127.0.0.1:%d' % self.args.port
        if not os.path.exists(jar):
            self.select_db(db)
        for _i in range(ok):
            sh(['curl', '-s', '-o', '/dev/null', '-c', jar, '-b', jar, base + '/web/login'])
        for _i in range(missing):
            sh(['curl', '-s', '-o', '/dev/null', '-c', jar, '-b', jar, base + '/fivenines-e2e-missing'])

    def wait_pushes(self, db, count, after, timeout=240):
        """Wait until the instance of `db` made `count` pushes after `after`."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = [p for p in self.all_pushes() if p['payload']['instance']['database'] == db
                   and p['received_at'] > after]
            if len(got) >= count:
                return got
            time.sleep(3)
        raise RuntimeError('timeout waiting for %d pushes of %s' % (count, db))

    def all_pushes(self):
        pushes = []
        with open(self.log_file) as f:
            for line in f:
                pushes.append(json.loads(line))
        return pushes

    @staticmethod
    def summary(push):
        p = push['payload']
        http = p['http'] or {}
        return {
            'instance_id': push['instance_id'],
            'seq': p['seq'],
            'window_seconds': p['window']['seconds'],
            'mode': (p['process'] or {}).get('mode'),
            'workers_reporting': len((p['process'] or {}).get('workers') or []),
            'request_capture': (p['process'] or {}).get('request_capture'),
            'requests': http.get('requests_by_status'),
            'p50_ms': (http.get('latency_ms') or {}).get('p50'),
            'p95_ms': (http.get('latency_ms') or {}).get('p95'),
            'sql_per_request': http.get('sql_queries_per_request'),
            'errors': p['logs']['error_count'] if p['logs'] else None,
            'events': [e['type'] for e in p['events']],
            'crons_active': (p['crons'] or {}).get('active_count'),
            'db_size_bytes': (p['database'] or {}).get('size_bytes'),
            'db_connections': ((p['database'] or {}).get('connections') or {}).get('total'),
            'cpu_host_pct': ((p['system'] or {}).get('host') or {}).get('cpu_usage_percent'),
            'odoo_rss_bytes': ((p['system'] or {}).get('odoo_processes') or {}).get('rss_bytes'),
            'cgroup': ((p['system'] or {}).get('cgroup') or {}).get('version'),
            'collector_errors': p['collector_errors'],
        }

    # -- scenarios -------------------------------------------------------
    def setup(self):
        self.serie = self.odoo('--version').stdout.split()[-1]
        prefix = 'fne2e_%s_' % self.serie.split('.')[0].split('~')[-1].replace('saas', '')
        self.db_a, self.db_b, self.db_copy, self.db_dup = (
            prefix + 'a', prefix + 'b', prefix + 'copy', prefix + 'dup')
        for db in (self.db_a, self.db_b, self.db_copy, self.db_dup):
            subprocess.run(['dropdb', '-h', self.args.db_host, '-U', self.args.db_user, '--if-exists', db],
                           capture_output=True)
        for db in (self.db_a, self.db_b):
            r = self.odoo('-d', db, '-i', 'fivenines_monitoring', '--stop-after-init',
                          '--http-port=%d' % self.args.port, '--log-level=warn')
            if r.returncode:
                raise RuntimeError(r.stderr[-2000:])
        self.log_file = os.path.join(self.tmp, 'pushes.jsonl')
        open(self.log_file, 'w').close()
        self.stub = subprocess.Popen([sys.executable, STUB, '--port', str(self.args.stub_port),
                                      '--enrollment-key', self.key, '--log-file', self.log_file, '--quiet'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)

    def scenario_threaded(self):
        conf = self.write_conf(0, db_filter='^%s$' % self.db_a)
        t0 = time.time()
        self.start(conf, [self.db_a])
        self.wait_pushes(self.db_a, 1, t0)     # enrollment + baseline push
        t1 = time.time()
        self.traffic(self.db_a, ok=20, missing=3)
        self.wait_pushes(self.db_a, 1, t1 + 1)
        # sum over the pushes after the traffic (it may straddle two minutes)
        time.sleep(65)
        pushes = [p for p in self.all_pushes() if p['payload']['instance']['database'] == self.db_a
                  and p['received_at'] > t1]
        self.stop()
        total = sum_status(pushes)
        self.report['scenarios']['workers_0'] = {
            'pushes_after_traffic': len(pushes), 'requests_counted': total,
            'last': self.summary(pushes[-1])}
        assert total.get('2xx', 0) >= 20 and total.get('4xx', 0) >= 3, total
        assert pushes[-1]['payload']['process']['mode'] == 'threaded'

    def scenario_prefork_multidb(self):
        conf = self.write_conf(2)
        t0 = time.time()
        self.start(conf, [self.db_a, self.db_b])
        self.select_db(self.db_a)
        self.select_db(self.db_b)
        self.wait_pushes(self.db_a, 1, t0)
        self.wait_pushes(self.db_b, 1, t0)
        time.sleep(12)  # let the selection requests be flushed and pushed first
        self.wait_pushes(self.db_a, 1, time.time())
        t1 = time.time()
        self.traffic(self.db_a, ok=30, missing=2)
        self.traffic(self.db_b, ok=7, missing=1)
        time.sleep(140)  # two cron rounds + spool flushes
        self.stop()
        out = {}
        for db, want in ((self.db_a, (30, 2)), (self.db_b, (7, 1))):
            pushes = [p for p in self.all_pushes() if p['payload']['instance']['database'] == db
                      and p['received_at'] > t1]
            total = sum_status(pushes)
            first_events = [e['type'] for p in self.all_pushes()
                            if p['payload']['instance']['database'] == db and p['received_at'] > t0
                            for e in p['payload']['events']]
            out[db] = {'pushes_after_traffic': len(pushes), 'requests_counted': total,
                       'events_since_start': sorted(set(first_events)),
                       'last': self.summary(pushes[-1])}
            # 'own requests only': exactly what we sent (+ nothing from the other db)
            assert total.get('2xx', 0) == want[0], (db, total)
            assert total.get('4xx', 0) == want[1], (db, total)
            assert pushes[-1]['payload']['process']['mode'] == 'prefork'
        times = sorted(p['received_at'] for p in self.all_pushes()
                       if p['payload']['instance']['database'] == self.db_a and p['received_at'] > t0)
        out['push_intervals_seconds_db_a'] = [round(b - a, 1) for a, b in zip(times, times[1:])]
        self.report['scenarios']['workers_2_two_databases'] = out
        assert 'server_restart' in out[self.db_a]['events_since_start'], out[self.db_a]

    def scenario_copy(self):
        a_id = psql(self.args, self.db_a, "SELECT value FROM ir_config_parameter WHERE key = 'fivenines.instance_id'")
        a_uuid = psql(self.args, self.db_a, "SELECT value FROM ir_config_parameter WHERE key = 'database.uuid'")
        sh(['createdb', '-h', self.args.db_host, '-U', self.args.db_user, '-T', self.db_a, self.db_copy])
        copy_uuid = psql(self.args, self.db_copy, "SELECT value FROM ir_config_parameter WHERE key = 'database.uuid'")
        conf = self.write_conf(0, db_filter='^%s$' % self.db_copy)
        t0 = time.time()
        self.start(conf, [self.db_copy])
        pushes = self.wait_pushes(self.db_copy, 1, t0)
        self.stop()
        copy_id = pushes[0]['instance_id']
        state = self.stub_state()
        inst = {i['instance_id']: i for i in state['instances']}
        self.report['scenarios']['copied_database'] = {
            'original_instance': a_id, 'copy_instance': copy_id,
            'copy_reason': inst[copy_id]['reason'],
            'copy_previous_instance_id': inst[copy_id]['previous_instance_id'],
            'pg_copy_keeps_uuid': a_uuid == copy_uuid,
        }
        assert copy_id != a_id
        assert inst[copy_id]['reason'] == 'fingerprint_changed'
        assert inst[copy_id]['previous_instance_id'] == a_id
        # Odoo's own duplicate (database manager / odoo-bin db duplicate),
        # run from a shell on the OTHER database (no connection to the source)
        code = 'import odoo.service.db as d\nd.exp_duplicate_database(%r, %r)\n' % (self.db_a, self.db_dup)
        subprocess.run([self.args.python, self.args.odoo_bin, 'shell', '-d', self.db_b, '--no-http',
                            '--addons-path=%s,%s' % (self.args.addons_path, REPO),
                            '--db_host=%s' % self.args.db_host, '--db_user=%s' % self.args.db_user,
                            '--log-level=warn'], input=code, capture_output=True, text=True)
        dup_uuid = psql(self.args, self.db_dup, "SELECT value FROM ir_config_parameter WHERE key = 'database.uuid'")
        self.report['scenarios']['copied_database']['odoo_duplicate_new_uuid'] = dup_uuid != a_uuid

    def teardown(self):
        self.stop()
        if getattr(self, 'stub', None):
            self.stub.terminate()
        secrets_ = {self.key}
        for db in (self.db_a, self.db_b, self.db_copy):
            try:
                value = psql(self.args, db, "SELECT value FROM ir_config_parameter "
                                            "WHERE key = 'fivenines.instance_secret'")
                if value:
                    secrets_.add(value)
            except Exception:  # noqa: BLE001
                pass
        found = False
        for name in os.listdir(self.tmp):
            if name.endswith('.log'):
                with open(os.path.join(self.tmp, name), errors='replace') as f:
                    text = f.read()
                found = found or any(s in text for s in secrets_)
        self.report['secrets_checked'] = len(secrets_)
        self.report['secret_in_odoo_logs'] = found
        if not self.args.keep:
            for db in (self.db_a, self.db_b, self.db_copy, self.db_dup):
                subprocess.run(['dropdb', '-h', self.args.db_host, '-U', self.args.db_user, '--if-exists', db],
                               capture_output=True)
            shutil.rmtree(self.tmp, True)


def sum_status(pushes):
    total = {}
    for p in pushes:
        for k, v in ((p['payload']['http'] or {}).get('requests_by_status') or {}).items():
            total[k] = total.get(k, 0) + v
    return total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--odoo-bin', required=True)
    parser.add_argument('--python', required=True)
    parser.add_argument('--addons-path', required=True)
    parser.add_argument('--db-host', default='localhost')
    parser.add_argument('--db-user', default=os.environ.get('USER'))
    parser.add_argument('--port', type=int, default=19069)
    parser.add_argument('--stub-port', type=int, default=19899)
    parser.add_argument('--keep', action='store_true', help='keep databases and logs')
    parser.add_argument('--only', choices=['threaded', 'prefork', 'copy'], action='append')
    args = parser.parse_args()
    run = Run(args)
    ok = True
    try:
        run.setup()
        for name in ('threaded', 'prefork', 'copy'):
            if args.only and name not in args.only:
                continue
            try:
                getattr(run, 'scenario_%s' % {'threaded': 'threaded', 'prefork': 'prefork_multidb',
                                              'copy': 'copy'}[name])()
            except Exception as e:  # noqa: BLE001
                ok = False
                run.report['scenarios'].setdefault(name, {})['error'] = '%s: %s' % (type(e).__name__, e)
                run.stop()
    finally:
        run.report['odoo'] = run.serie
        run.teardown()
    run.report['ok'] = ok
    print(json.dumps(run.report, indent=1))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
