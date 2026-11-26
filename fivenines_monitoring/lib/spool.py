# Part of Fivenines Monitoring. License LGPL-3.
"""Per-process spool files and the per-database state file.

Layout (one directory per database and PostgreSQL target):

    <tmp>/fivenines-<uid>/<dbname>-<hash8>/
        <pid>-<start>.json    cumulative counters of one Odoo process
        state.json            the cron's bookkeeping (acked baselines, backoff)
        state.lock            flock(2) target, so two pushes never overlap

* `<uid>` keeps two Odoo services running as different users apart, and lets
  us refuse a directory another local user pre-created (symlink games).
* `<hash8>` (sha1 of db_host:db_port:dbname) keeps two Odoo servers on one
  machine apart when both serve a database with the same name (two PostgreSQL
  clusters, both with a database called "odoo").
* `<pid>-<start>`: pids repeat across container restarts (master pid 1,
  workers 7, 8, 9...). The process start time makes the name unique so a new
  process never overwrites the last unacknowledged counters of a dead one.

Writes are atomic: write a temp file in the same directory, fsync-free
os.replace() over the final name. A reader sees the old or the new file,
never a torn one.
"""

import errno
import fcntl
import hashlib
import json
import os
import re
import tempfile
import time

STATE_FILE = 'state.json'
LOCK_FILE = 'state.lock'
_PROC_RE = re.compile(r'^(\d+)-(\d+)\.json$')
# A spool file not rewritten for this long belongs to a dead (or wedged)
# process whatever its pid says: drop it after its last delta was pushed.
STALE_AFTER = 3600


def _safe(name):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', name)[:64] or '_'


def base_dir(override=None):
    if override:
        return override
    return os.path.join(tempfile.gettempdir(), 'fivenines-%d' % os.getuid())


def db_dir(dbname, db_host='', db_port='', override=None):
    key = '%s:%s:%s' % (db_host or '', db_port or '', dbname)
    digest = hashlib.sha1(key.encode('utf-8')).hexdigest()[:8]
    return os.path.join(base_dir(override), '%s-%s' % (_safe(dbname), digest))


def ensure_dir(path):
    """mkdir -p with 0700, refusing a directory we do not own."""
    parent = os.path.dirname(path)
    for d in (parent, path):
        try:
            os.mkdir(d, 0o700)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        st = os.lstat(d)
        if not os.path.isdir(d) or os.path.islink(d) or st.st_uid != os.getuid():
            raise PermissionError('refusing spool directory not owned by us: %s' % d)
    return path


def proc_filename(pid, started_at):
    return '%d-%d.json' % (pid, int(started_at))


def write_json_atomic(path, data):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, separators=(',', ':'))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def list_process_files(directory):
    """[(key, path, pid, start)] for every process spool file."""
    out = []
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for name in names:
        m = _PROC_RE.match(name)
        if m:
            pid, start = int(m.group(1)), int(m.group(2))
            out.append(('%d-%d' % (pid, start), os.path.join(directory, name), pid, start))
        elif name.startswith('.tmp-'):
            # a temp file left by a process killed mid-write
            path = os.path.join(directory, name)
            try:
                if time.time() - os.stat(path).st_mtime > 300:
                    os.unlink(path)
            except OSError:
                pass
    return out


def process_alive(pid, started_at, psutil=None):
    """True when `pid` runs AND is the same process (start time within 2s)."""
    if psutil is None:
        import psutil  # noqa: PLC0415 - psutil is an Odoo dependency
    try:
        proc = psutil.Process(pid)
        return abs(proc.create_time() - started_at) < 2.0
    except Exception:  # NoSuchProcess, AccessDenied, ZombieProcess...
        return False


class StateLock:
    """Non-blocking exclusive flock on <dir>/state.lock.

    `acquired` is False when another process (the cron, or a "Send now" click)
    is already pushing for this database: the caller just skips this run.
    """

    def __init__(self, directory):
        self.path = os.path.join(directory, LOCK_FILE)
        self.fd = None
        self.acquired = False

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.acquired = True
        except OSError:
            self.acquired = False
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            if self.acquired:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
        return False
