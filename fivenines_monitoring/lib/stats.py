# Part of Fivenines Monitoring. License LGPL-3.
"""Cumulative per-process counters, and the delta / aggregation maths.

Every Odoo process keeps CUMULATIVE counters (since the process started) and
writes them to its spool file. The minute cron subtracts the snapshot it last
got acknowledged by Fivenines, so a failed push loses nothing: the next push
simply covers a longer window. This module is pure Python (no Odoo import) so
it can be unit tested anywhere.
"""

import copy

# Upper bounds (milliseconds) of the latency histogram buckets. The last bucket
# (index len(LATENCY_BOUNDS_MS)) catches everything above the last bound.
LATENCY_BOUNDS_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000)
STATUS_CLASSES = ('1xx', '2xx', '3xx', '4xx', '5xx', 'other')
ERROR_LEVELS = ('ERROR', 'CRITICAL')
# Distinct error fingerprints kept per process and database. Past that, new
# fingerprints only increment `errors.overflow` so memory stays bounded.
MAX_FINGERPRINTS = 100
STATS_VERSION = 1


def empty_stats():
    return {
        'v': STATS_VERSION,
        'http': {
            'status': {k: 0 for k in STATUS_CLASSES},
            'latency_buckets': [0] * (len(LATENCY_BOUNDS_MS) + 1),
            'latency_sum_ms': 0.0,
            'sql_queries': 0,
            'sql_time_ms': 0.0,
            # requests whose log line carried no usable perf_info
            'perf_missing': 0,
        },
        'logs': {
            'levels': {'WARNING': 0, 'ERROR': 0, 'CRITICAL': 0},
            'fingerprints': {},
            'overflow': 0,
        },
    }


def status_class(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return 'other'
    if 100 <= code < 600:
        return '%dxx' % (code // 100)
    return 'other'


def bucket_index(ms):
    for i, bound in enumerate(LATENCY_BOUNDS_MS):
        if ms <= bound:
            return i
    return len(LATENCY_BOUNDS_MS)


def record_request(stats, code, total_ms, sql_queries, sql_time_ms):
    http = stats['http']
    http['status'][status_class(code)] += 1
    if total_ms is None:
        http['perf_missing'] += 1
        return
    http['latency_buckets'][bucket_index(total_ms)] += 1
    http['latency_sum_ms'] += total_ms
    http['sql_queries'] += sql_queries
    http['sql_time_ms'] += sql_time_ms


def record_log(stats, level, fingerprint, info):
    logs = stats['logs']
    if level in logs['levels']:
        logs['levels'][level] += 1
    if level not in ERROR_LEVELS:
        return
    fps = logs['fingerprints']
    entry = fps.get(fingerprint)
    if entry is None:
        if len(fps) >= MAX_FINGERPRINTS:
            logs['overflow'] += 1
            return
        entry = dict(info, count=0)
        fps[fingerprint] = entry
    entry['count'] += 1


def _sub_num(a, b):
    return a - b


def delta(current, baseline):
    """current - baseline, for two cumulative snapshots of ONE process.

    Returns None when the baseline is not a prefix of current (any counter went
    backwards), which means the snapshots do not belong to the same process
    life: the caller then uses `current` whole.
    """
    if not baseline:
        return copy.deepcopy(current)
    try:
        out = empty_stats()
        ch, bh = current['http'], baseline['http']
        for k in STATUS_CLASSES:
            out['http']['status'][k] = ch['status'].get(k, 0) - bh['status'].get(k, 0)
        out['http']['latency_buckets'] = [
            c - b for c, b in zip(ch['latency_buckets'], bh['latency_buckets'])
        ]
        for k in ('latency_sum_ms', 'sql_queries', 'sql_time_ms', 'perf_missing'):
            out['http'][k] = ch.get(k, 0) - bh.get(k, 0)
        cl, bl = current['logs'], baseline['logs']
        for k in out['logs']['levels']:
            out['logs']['levels'][k] = cl['levels'].get(k, 0) - bl['levels'].get(k, 0)
        out['logs']['overflow'] = cl.get('overflow', 0) - bl.get('overflow', 0)
        for fp, entry in cl['fingerprints'].items():
            prev = bl['fingerprints'].get(fp, {}).get('count', 0)
            n = entry['count'] - prev
            if n:
                out['logs']['fingerprints'][fp] = dict(entry, count=n)
            if n < 0:
                return None
    except (KeyError, TypeError, ValueError):
        return None
    numbers = (
        list(out['http']['status'].values()) + out['http']['latency_buckets']
        + [out['http'][k] for k in ('latency_sum_ms', 'sql_queries', 'sql_time_ms', 'perf_missing')]
        + list(out['logs']['levels'].values()) + [out['logs']['overflow']]
    )
    if any(n < -1e-6 for n in numbers):
        return None
    return out


def merge_into(total, part):
    """Add one delta into an aggregate (both in the empty_stats() shape)."""
    th, ph = total['http'], part['http']
    for k in STATUS_CLASSES:
        th['status'][k] += ph['status'].get(k, 0)
    th['latency_buckets'] = [a + b for a, b in zip(th['latency_buckets'], ph['latency_buckets'])]
    for k in ('latency_sum_ms', 'sql_queries', 'sql_time_ms', 'perf_missing'):
        th[k] += ph.get(k, 0)
    tl, pl = total['logs'], part['logs']
    for k in tl['levels']:
        tl['levels'][k] += pl['levels'].get(k, 0)
    tl['overflow'] += pl.get('overflow', 0)
    for fp, entry in pl['fingerprints'].items():
        if fp in tl['fingerprints']:
            tl['fingerprints'][fp]['count'] += entry['count']
        else:
            tl['fingerprints'][fp] = dict(entry)
    return total


def percentile(buckets, q):
    """Approximate the q-quantile (0..1) of a bucketed distribution, in ms.

    Linear interpolation inside the bucket. Returns None when empty (unknown,
    never 0). Values in the overflow bucket are reported as the last bound.
    """
    total = sum(buckets)
    if total <= 0:
        return None
    target = q * total
    cumulative = 0
    for i, count in enumerate(buckets):
        if count <= 0:
            continue
        if cumulative + count >= target:
            lower = LATENCY_BOUNDS_MS[i - 1] if i > 0 else 0
            if i >= len(LATENCY_BOUNDS_MS):
                return float(LATENCY_BOUNDS_MS[-1])
            upper = LATENCY_BOUNDS_MS[i]
            fraction = (target - cumulative) / count
            return round(lower + (upper - lower) * fraction, 1)
        cumulative += count
    return float(LATENCY_BOUNDS_MS[-1])


def http_payload(agg, window_seconds, capture_enabled=True):
    """The `http` block of the push payload, from an aggregated delta."""
    if not capture_enabled:
        return None
    h = agg['http']
    total = sum(h['status'].values())
    timed = sum(h['latency_buckets'])

    def per_request(value):
        return round(value / timed, 3) if timed else None

    return {
        'requests_total': total,
        'requests_by_status': dict(h['status']),
        'requests_per_minute': (
            round(total * 60.0 / window_seconds, 3) if window_seconds and window_seconds > 0 else None
        ),
        'timed_requests': timed,
        'latency_ms': {
            'p50': percentile(h['latency_buckets'], 0.50),
            'p95': percentile(h['latency_buckets'], 0.95),
            'p99': percentile(h['latency_buckets'], 0.99),
            'mean': per_request(h['latency_sum_ms']),
        },
        'latency_histogram': {
            'bounds_ms': list(LATENCY_BOUNDS_MS),
            'counts': list(h['latency_buckets']),
        },
        'sql_queries_total': h['sql_queries'],
        'sql_time_ms_total': round(h['sql_time_ms'], 3),
        'sql_queries_per_request': per_request(h['sql_queries']),
        'sql_time_ms_per_request': per_request(h['sql_time_ms']),
    }


def logs_payload(agg, max_items=50):
    """The `logs` block: level counts plus the top fingerprints by count."""
    l = agg['logs']
    items = sorted(l['fingerprints'].items(), key=lambda kv: -kv[1]['count'])
    top = [dict(entry, fingerprint=fp) for fp, entry in items[:max_items]]
    return {
        'warning_count': l['levels'].get('WARNING', 0),
        'error_count': l['levels'].get('ERROR', 0),
        'critical_count': l['levels'].get('CRITICAL', 0),
        'fingerprints': top,
        'fingerprints_truncated': len(items) > max_items or l.get('overflow', 0) > 0,
    }
