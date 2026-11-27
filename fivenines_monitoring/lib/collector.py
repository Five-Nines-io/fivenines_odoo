# Part of Fivenines Monitoring. License LGPL-3.
"""In-process collection: one logging handler per Odoo process.

* HTTP requests come from the `werkzeug` access log line. Odoo attaches its
  PerfFilter to the `werkzeug` LOGGER (odoo/netsvc.py, 12.0+), so by the time a
  handler sees the record, `record.perf_info` = "query_count query_time
  remaining_time" (seconds). Total time = query_time + remaining_time. The
  status code is `record.args[1]` of werkzeug's '"%s" %s %s' line.
* WARNING / ERROR / CRITICAL records are counted per logger and fingerprint.
* Only records whose thread serves a database that has the module installed
  are counted (`threading.current_thread().dbname`, set by odoo/http.py for
  requests and by ir_cron for jobs), so a multi-database server keeps each
  database's numbers apart.

Counters are cumulative for the life of the process and flushed every
FLUSH_INTERVAL seconds (and at exit) to the spool directory of each database.
The handler never raises and never logs.
"""

import atexit
import copy
import hashlib
import logging
import os
import re
import threading
import time

from . import spool, stats

FLUSH_INTERVAL = 10
_ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_WERKZEUG_REQUEST_MSG = '"%s" %s %s'


def strip_ansi(value):
    return _ANSI.sub('', str(value))


def parse_perf_info(perf_info):
    """(query_count, query_time_s, remaining_time_s) or None."""
    if not perf_info:
        return None
    if isinstance(perf_info, (tuple, list)):
        perf_info = ' '.join(str(p) for p in perf_info)
    parts = strip_ansi(perf_info).split()
    if len(parts) < 3:
        return None
    try:
        return int(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return None


def perf_from_thread(thread):
    """Same maths as odoo.netsvc.PerfFilter, for when no perf_info was set."""
    try:
        query_count = thread.query_count
        query_time = thread.query_time
        perf_t0 = thread.perf_t0
    except AttributeError:
        return None
    return query_count, query_time, max(0.0, time.time() - perf_t0 - query_time)


# Werkzeug < 2.0 (e.g. 1.0.1 from Debian bullseye, used by the official odoo:16
# image) formats the line BEFORE logging: record.args is empty and the status
# sits at the end of the message: ... "GET /web HTTP/1.1" 200 1234
_PREFORMATTED_TAIL = re.compile(r'" (\d{3}|-) (?:\d+|-)\s*$')


def _preformatted_status(record):
    if record.args or not isinstance(record.msg, str):
        return None
    match = _PREFORMATTED_TAIL.search(strip_ansi(record.msg))
    return match.group(1) if match else None


def is_request_record(record):
    if record.name != 'werkzeug' or record.levelno != logging.INFO or not isinstance(record.msg, str):
        return False
    if isinstance(record.args, tuple) and len(record.args) >= 3 and _WERKZEUG_REQUEST_MSG in record.msg:
        return True  # werkzeug 2.x / 3.x: '"%s" %s %s' with (request line, code, size)
    return _preformatted_status(record) is not None


def request_status(record):
    if record.args:
        raw = strip_ansi(record.args[1]).strip()
    else:
        raw = _preformatted_status(record) or ''
    try:
        return int(raw)
    except ValueError:
        return None


def _short_path(path):
    if not path:
        return '?'
    path = path.replace('\\', '/')
    for marker in ('/odoo/addons/', '/addons/', '/site-packages/', '/odoo/'):
        idx = path.rfind(marker)
        if idx >= 0:
            return path[idx + 1:]
    return os.path.basename(path)


# Masks for messages that were formatted BEFORE logging (f-strings,
# `_logger.error('x %s' % v)`, `_logger.error(str(e))`, Werkzeug 1.x lines):
# there is no template, so values are blanked out instead. Order matters.
# Only this many characters are masked: the fingerprint uses the first 500
# and the template the first 300. Bounding the input keeps a huge token (a
# base64 blob in str(e)) from stalling the logging thread, which holds the
# handler lock while emit() runs.
MAX_MASKED = 2000
_MASKS = (
    (re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+'), '<email>'),
    (re.compile(r'\b[a-z][a-z0-9+.-]*://\S+', re.I), '<url>'),
    (re.compile(r'([?&][^=\s&]+)=[^&\s]*'), r'\1=?'),  # query strings
    # paired masks also match up to the end, for a value cut at MAX_MASKED
    (re.compile(r'=\([^)]*(?:\)|$)'), '=(?)'),      # psycopg2: Key (email)=(x)
    (re.compile(r'"[^"]*(?:"|$)'), '"?"'),
    (re.compile(r"'[^']*(?:'|$)"), "'?'"),
    (re.compile(r'\b[0-9a-f]{8,}\b', re.I), '<hex>'),
    (re.compile(r'\d+(?:[.,:]\d+)*'), 'N'),
)


def mask_values(text):
    """Mask the values of a pre-formatted message (bounded: MAX_MASKED chars).

    The regexes are quadratic on long runs without a match; a bounded prefix
    keeps the worst case to milliseconds. A token cut at the bound is dropped,
    so the tail of a value never escapes its mask.
    """
    cut = len(text) > MAX_MASKED
    if cut:
        text = re.sub(r'\S*$', '', text[:MAX_MASKED])
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text + ' [cut]' if cut else text


def log_fingerprint(record):
    """(fingerprint, info) grouping a log record by where it comes from.

    Uses the message TEMPLATE (record.msg, before % args), the exception type
    and the innermost traceback frame, so one root cause is one fingerprint and
    no argument value (customer data) ever leaves the instance. A message that
    arrives already formatted (no args) has no template: its values (numbers,
    quoted strings, emails, URLs, ids) are masked instead.
    """
    template = record.msg if isinstance(record.msg, str) else type(record.msg).__name__
    template = strip_ansi(template).strip()
    if not record.args:
        template = mask_values(template)
    exc_type = None
    origin = None
    if record.exc_info and record.exc_info[0] is not None:
        exc_type = getattr(record.exc_info[0], '__name__', str(record.exc_info[0]))
        tb = record.exc_info[2]
        while tb is not None and tb.tb_next is not None:
            tb = tb.tb_next
        if tb is not None:
            code = tb.tb_frame.f_code
            origin = '%s:%d %s' % (_short_path(code.co_filename), tb.tb_lineno, code.co_name)
    location = '%s:%d' % (_short_path(record.pathname), record.lineno or 0)
    key = '\x1f'.join((record.name, record.levelname, template[:500], exc_type or '', origin or location))
    fp = hashlib.sha1(key.encode('utf-8', 'replace')).hexdigest()[:16]
    info = {
        'logger': record.name[:200],
        'level': record.levelname,
        'message_template': template[:300],
        'exception_type': exc_type,
        'exception_origin': origin,
        'location': location,
    }
    return fp, info


class _DropBelow(logging.Filter):
    """Keeps a quieted logger quiet on Odoo's own handlers (see force_info)."""

    def __init__(self, name, level):
        super().__init__()
        self.logger_name = name
        self.level = level

    def filter(self, record):
        return not (record.name == self.logger_name and record.levelno < self.level)


class FiveninesHandler(logging.Handler):
    def __init__(self, collector):
        super().__init__(logging.NOTSET)
        self.collector = collector

    def handleError(self, record):  # never print tracebacks from monitoring
        pass

    def emit(self, record):
        try:
            if self.collector.ignore_pid == os.getpid():
                return  # prefork master (see Collector.ignore_pid)
            thread = threading.current_thread()
            dbname = getattr(thread, 'dbname', None)
            if not dbname or dbname not in self.collector.dbs:
                return
            if is_request_record(record):
                perf = parse_perf_info(getattr(record, 'perf_info', None)) or perf_from_thread(thread)
                if perf is None:
                    self.collector.on_request(dbname, request_status(record), None, 0, 0.0)
                else:
                    query_count, query_time, remaining = perf
                    self.collector.on_request(
                        dbname, request_status(record),
                        (query_time + remaining) * 1000.0, query_count, query_time * 1000.0,
                    )
                return
            if record.levelno >= logging.WARNING:
                level = 'CRITICAL' if record.levelno >= logging.CRITICAL else (
                    'ERROR' if record.levelno >= logging.ERROR else 'WARNING')
                if level == 'WARNING':
                    self.collector.on_log(dbname, level, None, None)
                else:
                    fp, info = log_fingerprint(record)
                    self.collector.on_log(dbname, level, fp, info)
        except Exception:  # noqa: BLE001 - monitoring must never break logging
            pass


class Collector:
    """Process-wide singleton (see COLLECTOR below)."""

    def __init__(self):
        self.dbs = {}  # dbname -> spool directory
        self.handler = None
        # The prefork master serves no request: counting there would attribute
        # its own warnings to the last preloaded database and start the flusher
        # thread before the workers are forked. Set by the Odoo model.
        self.ignore_pid = None
        self.werkzeug_capture = None  # 'native' | 'forced' | 'disabled'
        self._reset_process()
        if hasattr(os, 'register_at_fork'):
            os.register_at_fork(after_in_child=self._reset_process)
        atexit.register(self._atexit)

    # -- process life -----------------------------------------------------
    def _reset_process(self):
        # After a fork: fresh lock (the parent's could be held by a thread that
        # does not exist here), fresh counters, no flusher thread yet.
        self._lock = threading.Lock()
        self._pid = os.getpid()
        self._started_at = None
        self._data = {}
        self._dirty = set()
        self._thread = None
        self._stop = threading.Event()

    def _check_fork(self):
        if self._pid != os.getpid():  # fork without register_at_fork
            self._reset_process()

    @property
    def started_at(self):
        if self._started_at is None:
            try:
                import psutil  # noqa: PLC0415
                self._started_at = psutil.Process(os.getpid()).create_time()
            except Exception:  # noqa: BLE001
                self._started_at = time.time()
        return self._started_at

    def _ensure_thread(self):
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._run, name='fivenines.flusher', daemon=True)
            self._thread.start()

    def _run(self):
        while not self._stop.wait(FLUSH_INTERVAL):
            if self._pid != os.getpid():
                return
            try:
                self.flush()
            except Exception:  # noqa: BLE001
                pass

    def _atexit(self):
        try:
            if self._pid == os.getpid():
                self.flush()
        except Exception:  # noqa: BLE001
            pass

    # -- configuration ----------------------------------------------------
    def register_db(self, dbname, directory):
        self.dbs[dbname] = directory

    def unregister_db(self, dbname):
        self.dbs.pop(dbname, None)

    def install(self, force_werkzeug_info=True):
        """Attach the handler to the root logger, once per process."""
        root = logging.getLogger()
        if self.handler is None or self.handler not in root.handlers:
            self.handler = FiveninesHandler(self)
            root.addHandler(self.handler)
        if self.werkzeug_capture is None:
            self.werkzeug_capture = self.force_info('werkzeug') if force_werkzeug_info else (
                'native' if logging.getLogger('werkzeug').isEnabledFor(logging.INFO) else 'disabled')
        return self.handler

    def force_info(self, name):
        """Make sure INFO records of logger `name` are created.

        With `log_level = warn` (or `--log-handler werkzeug:WARNING`) Odoo sets
        the werkzeug logger to WARNING, so no access record is ever created and
        request metrics would silently read 0. We lower that logger to INFO and
        add a filter to every other root handler so the log OUTPUT is unchanged:
        only our handler sees the extra records.
        """
        target = logging.getLogger(name)
        level = target.getEffectiveLevel()
        if level <= logging.INFO:
            return 'native'
        drop = _DropBelow(name, level)
        root = logging.getLogger()
        for h in list(root.handlers) + list(target.handlers):
            if h is not self.handler:
                h.addFilter(drop)
        target.setLevel(logging.INFO)
        return 'forced'

    # -- recording (called with the logging handler lock held) ------------
    def _stats(self, dbname):
        self._check_fork()
        data = self._data.get(dbname)
        if data is None:
            data = self._data[dbname] = stats.empty_stats()
        self._dirty.add(dbname)
        self._ensure_thread()
        return data

    def on_request(self, dbname, code, total_ms, sql_queries, sql_time_ms):
        with self._lock:
            stats.record_request(self._stats(dbname), code, total_ms, sql_queries, sql_time_ms)

    def on_log(self, dbname, level, fingerprint, info):
        with self._lock:
            stats.record_log(self._stats(dbname), level, fingerprint, info)

    # -- flushing ---------------------------------------------------------
    def snapshot(self, dbname):
        with self._lock:
            self._check_fork()
            data = self._data.get(dbname)
            return None if data is None else copy.deepcopy(data)

    def flush(self, dbname=None):
        """Write this process's cumulative counters (atomic rename)."""
        with self._lock:
            self._check_fork()
            names = [dbname] if dbname else list(self._dirty)
            todo = [(n, copy.deepcopy(self._data[n])) for n in names if n in self._data]
            self._dirty.difference_update(names)
        started_at = self.started_at
        for name, data in todo:
            directory = self.dbs.get(name)
            if not directory:
                continue
            try:
                spool.ensure_dir(directory)
                spool.write_json_atomic(
                    os.path.join(directory, spool.proc_filename(os.getpid(), started_at)),
                    {
                        'pid': os.getpid(),
                        'ppid': os.getppid(),
                        'started_at': started_at,
                        'flushed_at': time.time(),
                        'stats': data,
                    },
                )
            except Exception:  # noqa: BLE001
                with self._lock:
                    self._dirty.add(name)



COLLECTOR = Collector()
