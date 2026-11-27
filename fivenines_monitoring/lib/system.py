# Part of Fivenines Monitoring. License LGPL-3.
"""System metrics: psutil for the host, cgroup files for the container.

In a container psutil reports the whole host. When the process runs in a
cgroup with limits (Docker, Kubernetes, Odoo.sh, a systemd slice), the cgroup
files under /sys/fs/cgroup hold the real limit and usage, so we report both.

Rates (CPU %) need two samples: the caller passes the previous raw sample and
gets the new one back, so the percentage covers the time between two cron runs.
Anything that cannot be read is None (unknown), never 0.
"""

import os
import time

CGROUP_ROOT = '/sys/fs/cgroup'
# cgroup v1 reports "no limit" as a huge number (PAGE_COUNTER_MAX * page size).
V1_UNLIMITED = 1 << 60


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _kv(text):
    out = {}
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[0]] = _int(parts[1])
    return out


def _self_cgroups(proc_cgroup):
    """{controller: path} (v1) and the '' entry (v2) from /proc/self/cgroup."""
    out = {}
    for line in (_read(proc_cgroup) or '').splitlines():
        parts = line.split(':', 2)
        if len(parts) != 3:
            continue
        _, controllers, path = parts
        for c in (controllers.split(',') if controllers else ['']):
            out[c] = path
    return out


def _pick_dir(base, path):
    """The cgroup dir of this process, falling back to the mount root.

    Inside a container with a private cgroup namespace /proc/self/cgroup shows
    "/" and the files sit at the mount root; on a host it shows the full path
    (e.g. /system.slice/odoo.service).
    """
    candidate = os.path.join(base, (path or '/').lstrip('/'))
    return candidate if os.path.isdir(candidate) else base


def read_cgroup(root=CGROUP_ROOT, proc_cgroup='/proc/self/cgroup'):
    """Raw cgroup counters, or None when there is no readable cgroup."""
    paths = _self_cgroups(proc_cgroup)
    if os.path.exists(os.path.join(root, 'cgroup.controllers')):
        d = _pick_dir(root, paths.get(''))
        cpu_max = (_read(os.path.join(d, 'cpu.max')) or '').split()
        quota = None
        if len(cpu_max) == 2 and cpu_max[0] != 'max':
            q, p = _int(cpu_max[0]), _int(cpu_max[1])
            quota = q / p if q and p else None
        mem_max = _read(os.path.join(d, 'memory.max'))
        cpu_stat = _kv(_read(os.path.join(d, 'cpu.stat')))
        mem_stat = _kv(_read(os.path.join(d, 'memory.stat')))
        usage_usec = cpu_stat.get('usage_usec')
        throttled_usec = cpu_stat.get('throttled_usec')
        return {
            'version': 2,
            'path': paths.get(''),
            'cpu_limit_cores': quota,
            'cpu_usage_seconds': usage_usec / 1e6 if usage_usec is not None else None,
            'cpu_throttled_seconds': throttled_usec / 1e6 if throttled_usec is not None else None,
            'memory_usage_bytes': _int(_read(os.path.join(d, 'memory.current'))),
            'memory_limit_bytes': None if mem_max in (None, 'max') else _int(mem_max),
            'memory_unlimited': None if mem_max is None else mem_max == 'max',
            'memory_inactive_file_bytes': mem_stat.get('inactive_file'),
            'pids_current': _int(_read(os.path.join(d, 'pids.current'))),
            'pids_limit': (lambda v: None if v in (None, 'max') else _int(v))(
                _read(os.path.join(d, 'pids.max'))),
        }
    mem_base = os.path.join(root, 'memory')
    if os.path.isdir(mem_base):
        mem = _pick_dir(mem_base, paths.get('memory'))
        cpu_base = next((os.path.join(root, n) for n in ('cpu,cpuacct', 'cpu', 'cpuacct')
                         if os.path.isdir(os.path.join(root, n))), None)
        cpu = _pick_dir(cpu_base, paths.get('cpu') or paths.get('cpuacct')) if cpu_base else None
        quota = period = usage_ns = throttled_ns = None
        if cpu:
            quota = _int(_read(os.path.join(cpu, 'cpu.cfs_quota_us')))
            period = _int(_read(os.path.join(cpu, 'cpu.cfs_period_us')))
            usage_ns = _int(_read(os.path.join(cpu, 'cpuacct.usage')))
            throttled_ns = _kv(_read(os.path.join(cpu, 'cpu.stat'))).get('throttled_time')
        limit = _int(_read(os.path.join(mem, 'memory.limit_in_bytes')))
        mem_stat = _kv(_read(os.path.join(mem, 'memory.stat')))
        pids_dir = _pick_dir(os.path.join(root, 'pids'), paths.get('pids'))
        pids_max = _read(os.path.join(pids_dir, 'pids.max'))
        return {
            'version': 1,
            'path': paths.get('memory'),
            'cpu_limit_cores': quota / period if quota and quota > 0 and period else None,
            'cpu_usage_seconds': usage_ns / 1e9 if usage_ns is not None else None,
            'cpu_throttled_seconds': throttled_ns / 1e9 if throttled_ns is not None else None,
            'memory_usage_bytes': _int(_read(os.path.join(mem, 'memory.usage_in_bytes'))),
            'memory_limit_bytes': None if limit is None or limit >= V1_UNLIMITED else limit,
            'memory_unlimited': None if limit is None else limit >= V1_UNLIMITED,
            'memory_inactive_file_bytes': mem_stat.get('total_inactive_file', mem_stat.get('inactive_file')),
            'pids_current': _int(_read(os.path.join(pids_dir, 'pids.current'))),
            'pids_limit': None if pids_max in (None, 'max') else _int(pids_max),
        }
    return None


def _host_cpu_sample(psutil):
    t = psutil.cpu_times()
    idle = t.idle + getattr(t, 'iowait', 0.0)
    total = sum(t)
    return {'total': total, 'idle': idle}


def _pct(numerator, denominator):
    if numerator is None or not denominator or denominator <= 0:
        return None
    return round(max(0.0, min(100.0, numerator * 100.0 / denominator)), 2)


def odoo_processes(psutil, server_pid):
    """Odoo master + children: count, total RSS, and raw CPU seconds."""
    try:
        master = psutil.Process(server_pid)
        procs = [master] + master.children(recursive=True)
    except Exception:  # noqa: BLE001
        return None
    rss = 0
    cpu_seconds = 0.0
    count = 0
    for p in procs:
        try:
            with p.oneshot():
                rss += p.memory_info().rss
                t = p.cpu_times()
                cpu_seconds += t.user + t.system
            count += 1
        except Exception:  # noqa: BLE001 - process exited meanwhile
            continue
    return {'count': count, 'rss_bytes': rss, 'cpu_seconds': cpu_seconds}


def collect(prev, data_dir, server_pid, now=None, psutil=None, cgroup_root=CGROUP_ROOT,
            proc_cgroup='/proc/self/cgroup'):
    """(system_block, raw_sample_to_keep, errors)."""
    if psutil is None:
        import psutil  # noqa: PLC0415
    now = now or time.time()
    prev = prev or {}
    errors = []
    sample = {'at': now}

    def guard(name, fn, default=None):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            errors.append({'collector': 'system.%s' % name, 'type': type(e).__name__,
                           'message': str(e)[:200]})
            return default

    elapsed = now - prev['at'] if prev.get('at') else None
    host_cpu = guard('cpu', lambda: _host_cpu_sample(psutil))
    host_cpu_pct = None
    if host_cpu:
        sample['host_cpu'] = host_cpu
        p = prev.get('host_cpu')
        if p:
            dt = host_cpu['total'] - p['total']
            host_cpu_pct = _pct(dt - (host_cpu['idle'] - p['idle']), dt)

    vm = guard('memory', psutil.virtual_memory)
    swap = guard('swap', psutil.swap_memory)
    load = guard('load', os.getloadavg)
    disk = guard('disk', lambda: psutil.disk_usage(data_dir)) if data_dir and os.path.isdir(data_dir) else None
    cpu_count = guard('cpu_count', psutil.cpu_count)

    cg = guard('cgroup', lambda: read_cgroup(cgroup_root, proc_cgroup))
    cgroup_block = None
    if cg:
        cg_cpu_pct = None
        if cg.get('cpu_usage_seconds') is not None:
            sample['cg_cpu'] = cg['cpu_usage_seconds']
            if prev.get('cg_cpu') is not None and elapsed:
                cores = cg['cpu_limit_cores'] or cpu_count
                cg_cpu_pct = _pct(cg['cpu_usage_seconds'] - prev['cg_cpu'], elapsed * cores) if cores else None
        throttled_delta = None
        if cg.get('cpu_throttled_seconds') is not None:
            sample['cg_throttled'] = cg['cpu_throttled_seconds']
            if prev.get('cg_throttled') is not None:
                throttled_delta = round(max(0.0, cg['cpu_throttled_seconds'] - prev['cg_throttled']), 3)
        usage = cg.get('memory_usage_bytes')
        inactive = cg.get('memory_inactive_file_bytes')
        cgroup_block = {
            'version': cg['version'],
            'path': cg.get('path'),
            'cpu_limit_cores': round(cg['cpu_limit_cores'], 3) if cg.get('cpu_limit_cores') else None,
            'cpu_usage_percent': cg_cpu_pct,
            'cpu_throttled_seconds': throttled_delta,
            'memory_usage_bytes': usage,
            'memory_working_set_bytes': (usage - inactive) if usage is not None and inactive is not None else None,
            'memory_limit_bytes': cg.get('memory_limit_bytes'),
            'memory_unlimited': cg.get('memory_unlimited'),
            'pids_current': cg.get('pids_current'),
            'pids_limit': cg.get('pids_limit'),
        }

    procs = guard('processes', lambda: odoo_processes(psutil, server_pid)) if server_pid else None
    odoo_cpu_pct = None
    if procs:
        sample['odoo_cpu'] = procs['cpu_seconds']
        sample['odoo_pid'] = server_pid
        if prev.get('odoo_cpu') is not None and prev.get('odoo_pid') == server_pid and elapsed and cpu_count:
            # can drop when a worker is recycled (its CPU time leaves the sum)
            d = procs['cpu_seconds'] - prev['odoo_cpu']
            odoo_cpu_pct = _pct(d, elapsed * cpu_count) if d >= 0 else None

    block = {
        'host': {
            'cpu_count': cpu_count,
            'cpu_usage_percent': host_cpu_pct,
            'load_average': [round(x, 2) for x in load] if load else None,
            'memory_total_bytes': vm.total if vm else None,
            'memory_available_bytes': vm.available if vm else None,
            'memory_used_percent': vm.percent if vm else None,
            'swap_total_bytes': swap.total if swap else None,
            'swap_used_bytes': swap.used if swap else None,
            'process_count': guard('pids', lambda: len(psutil.pids())),
        },
        'cgroup': cgroup_block,
        'disk': {
            'path': data_dir,
            'total_bytes': disk.total,
            'used_bytes': disk.used,
            'free_bytes': disk.free,
            'used_percent': disk.percent,
        } if disk else None,
        'odoo_processes': {
            'count': procs['count'],
            'rss_bytes': procs['rss_bytes'],
            'cpu_usage_percent': odoo_cpu_pct,
        } if procs else None,
        'sample_interval_seconds': round(elapsed, 3) if elapsed else None,
    }
    return block, sample, errors
