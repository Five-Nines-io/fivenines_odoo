# Part of Fivenines Monitoring. License LGPL-3.
"""HTTP client for the Fivenines Odoo API (see docs/api-contract.md).

The secret only ever travels in the Authorization header. It is never put in
a URL, a log line or an exception message: errors are reported by status code
and a short server message only.
"""

import gzip
import json
import logging
from urllib.parse import urlsplit

import requests

_logger = logging.getLogger(__name__)

DEFAULT_API_URL = 'https://api.fivenines.io'
ENROLL_PATH = '/odoo/v1/enroll'
PUSH_PATH = '/odoo/v1/collect'
# Seconds, applied by requests to the connect AND to each read. The cron must
# never hang on the network: worst case a run waits ~20 s, then the next
# minute tries again. (A single number, not a (connect, read) tuple: Odoo's
# test harness compares the timeout with an int.)
TIMEOUT = 10
MAX_RETRY_AFTER = 3600

# Result kinds, one per behaviour the module has (docs/api-contract.md#errors)
OK = 'ok'
UNAUTHORIZED = 'unauthorized'          # 401: secret revoked / key invalid
PAYMENT_REQUIRED = 'payment_required'  # 402
FORBIDDEN = 'forbidden'                # 403: instance limit / instance disabled
CONFLICT = 'conflict'                  # 409: fingerprint conflict
REJECTED = 'rejected'                  # 400, 413, 422: payload refused
RATE_LIMITED = 'rate_limited'          # 429
RETRY = 'retry'                        # 404, 5xx, timeouts, connection errors


class Result:
    __slots__ = ('kind', 'status', 'data', 'message', 'retry_after')

    def __init__(self, kind, status=None, data=None, message=None, retry_after=None):
        self.kind = kind
        self.status = status
        self.data = data or {}
        self.message = message
        self.retry_after = retry_after

    @property
    def ok(self):
        return self.kind == OK

    def __repr__(self):
        return '<Result %s status=%s message=%r>' % (self.kind, self.status, self.message)


def is_loopback(host):
    host = (host or '').lower().strip('[]')
    return host in ('localhost', '::1') or host.startswith('127.')


def check_api_url(url, allow_insecure=False):
    """Normalized base URL, or ValueError. HTTPS only, except loopback (the stub)."""
    url = (url or '').strip().rstrip('/')
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('invalid Fivenines API URL')
    if parts.scheme == 'http' and not (allow_insecure or is_loopback(parts.hostname)):
        raise ValueError('the Fivenines API URL must use https')
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError('the Fivenines API URL must not carry credentials, a query or a fragment')
    return url


def _retry_after(response):
    value = response.headers.get('Retry-After')
    try:
        return max(0, min(MAX_RETRY_AFTER, int(float(value))))
    except (TypeError, ValueError):
        return None


def classify(status, body, retry_after=None):
    message = None
    if isinstance(body, dict):
        message = body.get('message') or body.get('error')
        if message is not None:
            message = str(message)[:300]
    if 200 <= status < 300:
        return Result(OK, status, body if isinstance(body, dict) else {}, message)
    kind = {
        401: UNAUTHORIZED,
        402: PAYMENT_REQUIRED,
        403: FORBIDDEN,
        409: CONFLICT,
        400: REJECTED,
        413: REJECTED,
        422: REJECTED,
        429: RATE_LIMITED,
    }.get(status, RETRY)
    return Result(kind, status, body if isinstance(body, dict) else {}, message, retry_after)


class Client:
    def __init__(self, base_url, user_agent, timeout=TIMEOUT, session=None):
        self.base_url = base_url
        self.user_agent = user_agent
        self.timeout = timeout
        self.session = session or requests

    def _post(self, path, token, payload):
        body = gzip.compress(json.dumps(payload, separators=(',', ':'), default=str).encode('utf-8'))
        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json',
            'Content-Encoding': 'gzip',
            'Accept': 'application/json',
            'User-Agent': self.user_agent,
        }
        try:
            response = self.session.post(
                self.base_url + path, data=body, headers=headers,
                timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.Timeout:
            return Result(RETRY, None, message='timeout')
        except requests.exceptions.RequestException as e:
            # str(e) holds the URL (no secret: it is only in a header)
            return Result(RETRY, None, message='%s: %s' % (type(e).__name__, str(e)[:200]))
        try:
            data = response.json()
        except ValueError:
            data = None
        return classify(response.status_code, data, _retry_after(response))

    def enroll(self, enrollment_key, payload):
        result = self._post(ENROLL_PATH, enrollment_key, payload)
        if result.ok and not (result.data.get('token') and result.data.get('instance_id')):
            return Result(RETRY, result.status, message='enrollment answer without token/instance_id')
        return result

    def push(self, secret, payload):
        return self._post(PUSH_PATH, secret, payload)


def backoff_delay(failures, base=60, cap=900):
    """Seconds to wait after `failures` consecutive retryable failures.

    The first 3 failures retry at the next minute; then 2, 4, 8 min, capped at
    15 min. A down Fivenines therefore costs each instance at most one short
    request every 15 minutes, and recovery is seen within 15 minutes.
    """
    if failures <= 3:
        return base
    return min(cap, base * 2 ** (failures - 3))
