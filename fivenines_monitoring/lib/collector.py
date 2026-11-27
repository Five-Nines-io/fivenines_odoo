# Part of Fivenines Monitoring. License LGPL-3.
"""In-process collection: one logging handler per Odoo process.

* HTTP requests come from the `werkzeug` access log line. Odoo attaches its
  PerfFilter to the `werkzeug` LOGGER (odoo/netsvc.py, 12.0+), so by the time a
  handler sees the record, `record.perf_info` = "query_count query_time
  remaining_time" (seconds). Total time = query_time + remaining_time. The
  status code is `record.args[1]` of werkzeug's '"%s" %s %s' line.
  Odoo 20.0 serves HTTP itself (h11, odoo/http/server.py): its access line is
  an INFO record of the `odoo.http.server` logger carrying the status
  (`http_response_status`) and the timings (`query_count`, `query_time`,
  `remaining_time`) as record attributes.
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
import importlib.util
import logging
import os
import re
import threading
import time
import traceback

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


def perf_from_record(record):
    """Odoo 20.0 access records carry the timings as attributes."""
    try:
        query_count = int(record.query_count)
        query_time = float(record.query_time)
        remaining = float(record.remaining_time)
    except (AttributeError, TypeError, ValueError):
        return None
    return query_count, query_time, max(0.0, remaining)


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


ACCESS_LOGGER_ODOO_HTTP = 'odoo.http.server'  # Odoo 20.0+


def is_request_record(record):
    if record.name == ACCESS_LOGGER_ODOO_HTTP:
        return record.levelno == logging.INFO and type(
            getattr(record, 'http_response_status', None)) is int
    if record.name != 'werkzeug' or record.levelno != logging.INFO or not isinstance(record.msg, str):
        return False
    if isinstance(record.args, tuple) and len(record.args) >= 3 and _WERKZEUG_REQUEST_MSG in record.msg:
        return True  # werkzeug 2.x / 3.x: '"%s" %s %s' with (request line, code, size)
    return _preformatted_status(record) is not None


def request_status(record):
    if record.name == ACCESS_LOGGER_ODOO_HTTP:
        return record.http_response_status
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
    (re.compile(r'=\([^)]*\)'), '=(?)'),            # psycopg2: Key (email)=(x)
    (re.compile(r'"[^"]*"'), '"?"'),
    (re.compile(r"'[^']*'"), "'?'"),
    (re.compile(r'\b[0-9a-f]{8,}\b', re.I), '<hex>'),
    (re.compile(r'\d+(?:[.,:]\d+)*'), 'N'),
)
# Credentials are masked in every text that leaves the instance, messages on
# or off: they are not customer data, they are secrets. Every quantifier is
# bounded (no quadratic backtracking) and the inputs are bounded too.
MAX_MESSAGE = 2000
MAX_TRACEBACK = 8000
_SECRET_NAME = (r'[\w-]{0,40}(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|'
                r'private[_-]?key|session[_-]?id|signature|credentials?)')
_CREDENTIAL_MASKS = (
    # user:password@ in any URL or DSN (postgres://, https://, smtp://...)
    (re.compile(r'(\b[a-zA-Z][a-zA-Z0-9+.-]{0,30}://)[^\s/@:]{1,256}:[^\s/@]{1,256}@'), r'\1***:***@'),
    # Authorization / Proxy-Authorization values
    (re.compile(r'(?i)\b((?:proxy-)?authorization)(["\']?\s{0,4}[:=]\s{0,4}["\']?)'
                r'((?:bearer|basic|token|digest)\s{1,4})?[^\s"\',;]{1,4096}'), r'\1\2\3***'),
    # password=..., "api_key": "...", ?token=..., secret: ...
    (re.compile(r'(?i)\b(' + _SECRET_NAME + r')(["\']?\s{0,4}[:=]\s{0,4}["\']?)([^\s"\',;&}]{1,4096})'),
     r'\1\2***'),
    (re.compile(r'(?i)\bbearer\s{1,4}[A-Za-z0-9._~+/=-]{8,4096}'), 'Bearer ***'),
    (re.compile(r'\beyJ[\w-]{4,4096}\.[\w-]{4,4096}\.[\w-]{0,4096}'), '<jwt>'),
    (re.compile(r'\b[0-9a-fA-F]{32,4096}\b'), '<hex>'),
)


def mask_credentials(text):
    if not text:
        return text
    for pattern, replacement in _CREDENTIAL_MASKS:
        text = pattern.sub(replacement, text)
    return text


def _bounded(text, limit, keep='head'):
    """Cut to `limit` chars at a whitespace, so no credential is cut in half
    (a half token would no longer match its mask)."""
    if len(text) <= limit:
        return text
    if keep == 'tail':
        text = text[-limit:]
        first = min([i for i in (text.find(' '), text.find('\n')) if i >= 0] or [len(text)])
        return '[cut] ' + text[first + 1:]
    text = text[:limit]
    last = max(text.rfind(' '), text.rfind('\n'), text.rfind('\t'))
    return text[:last + 1] + '[cut]'


# Credentials are masked BEFORE the length cut, on a window a bit larger than
# the bound: a cut that fell inside "password: value" would otherwise drop the
# name and leave the value bare. MAX_MASKED_VALUE is the {1,4096} bound of the
# name=value masks in _CREDENTIAL_MASKS; keep the two in step.
MAX_MASKED_VALUE = 4096
MASK_MARGIN = MAX_MASKED_VALUE + 512


def _masked_bounded(text, limit, keep='head'):
    if len(text) <= limit + MASK_MARGIN:
        window = text
    elif keep == 'tail':
        window = text[-(limit + MASK_MARGIN):]
        # open edge on a whole line, else on a whitespace: no token split there
        edge = window.find('\n')
        if edge < 0:
            edge = min([i for i in (window.find(' '), window.find('\t')) if i >= 0] or [-1])
        window = window[edge + 1:]
    else:
        window = text[:limit + MASK_MARGIN]
        edge = max(window.rfind(' '), window.rfind('\n'), window.rfind('\t'))
        if edge > 0:
            window = window[:edge]
    return _bounded(mask_credentials(window), limit, keep)


def error_sample(record):
    """The latest occurrence of an error group: message and traceback, bounded,
    with credentials masked. Sent unless the database turned messages off.
    Built at most once every SAMPLE_EVERY seconds per group (stats.record_log)."""
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - a broken %-format must not lose the sample
        message = str(record.msg)
    tb = record.exc_text or None
    if tb is None and record.exc_info and record.exc_info[0] is not None:
        tb = ''.join(traceback.format_exception(*record.exc_info))
    if record.stack_info:
        tb = (tb + '\n' if tb else '') + record.stack_info
    return {
        'message': _masked_bounded(strip_ansi(message), MAX_MESSAGE),
        'traceback': _masked_bounded(tb, MAX_TRACEBACK, keep='tail') if tb else None,
        'at': record.created,
    }


def mask_values(text):
    """Mask the values of a pre-formatted message.

    A message longer than MAX_MASKED is cut, and only its text before the first
    quote or `=(` is kept: a value whose closing delimiter was cut off can then
    never escape its mask (no quote pairing on cut text), and the regexes, which
    are quadratic on long runs without a match, see a bounded input.
    """
    cut = len(text) > MAX_MASKED
    if cut:
        text = text[:MAX_MASKED]
        ends = [i for i in (text.find('"'), text.find("'"), text.find('=(')) if i >= 0]
        if ends:
            text = text[:min(ends)]
        else:  # drop the token cut at the bound (linear: no regex)
            text = text[:max(text.rfind(' '), text.rfind('\n'), text.rfind('\t')) + 1]
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
    template = mask_credentials(template)
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


def access_logger_name():
    """The logger of the HTTP access line in the running Odoo."""
    try:  # Odoo 20.0+: odoo.http is a package with its own server
        found = importlib.util.find_spec('odoo.http.server_log') is not None
    except (ImportError, ValueError):  # 16.0-19.0: odoo.http is a module
        found = False
    return ACCESS_LOGGER_ODOO_HTTP if found else 'werkzeug'


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
                perf = (perf_from_record(record) if record.name == ACCESS_LOGGER_ODOO_HTTP
                        else parse_perf_info(getattr(record, 'perf_info', None))) or perf_from_thread(thread)
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
                    # built lazily: at most once every SAMPLE_EVERY s per group
                    self.collector.on_log(dbname, level, fp, info, lambda: error_sample(record))
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

    def install(self, force_werkzeug_info=True, access_logger='werkzeug'):
        """Attach the handler to the root logger, once per process.

        `access_logger` is the logger of the HTTP access line: `werkzeug` up
        to Odoo 19.0, `odoo.http.server` from 20.0 (see access_logger_name).
        """
        root = logging.getLogger()
        if self.handler is None or self.handler not in root.handlers:
            self.handler = FiveninesHandler(self)
            root.addHandler(self.handler)
        if self.werkzeug_capture is None:
            self.werkzeug_capture = self.force_info(access_logger) if force_werkzeug_info else (
                'native' if logging.getLogger(access_logger).isEnabledFor(logging.INFO) else 'disabled')
        return self.handler

    def force_info(self, name):
        """Make sure INFO records of logger `name` are created.

        With `log_level = warn` (or `--log-handler werkzeug:WARNING`) Odoo sets
        the access logger to WARNING, so no access record is ever created and
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

    def on_log(self, dbname, level, fingerprint, info, sample=None):
        with self._lock:
            stats.record_log(self._stats(dbname), level, fingerprint, info, sample)

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
