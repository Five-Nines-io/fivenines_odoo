# Part of Fivenines Monitoring. License LGPL-3.
"""HTTP client for the Fivenines Odoo API (see docs/api-contract.md).

The secret only ever travels in the Authorization header. It is never put in
a URL, a log line or an exception message: errors are reported by status code
and a short server message only.
"""

import gzip
import ipaddress
import json
import re
from urllib.parse import urlsplit

import requests

DEFAULT_API_URL = 'https://api.fivenines.io'
ENROLL_PATH = '/odoo/v1/enroll'
PUSH_PATH = '/odoo/v1/collect'
# Seconds, applied by requests to the connect AND to each read. The cron must
# never hang on the network: worst case a run waits ~20 s, then the next
# minute tries again. (A single number, not a (connect, read) tuple: Odoo's
# test harness compares the timeout with an int.)
TIMEOUT = 10
MAX_RETRY_AFTER = 3600
# While waiting for approval: check every retry_after seconds (the server's
# figure, default 900), bounded so a proposal is never left silent for long
# (Fivenines drops a proposal silent for 3 days) nor polled every minute.
PENDING_DEFAULT = 900
PENDING_MIN, PENDING_MAX = 300, 21600

# Result kinds, one per behaviour the module has (docs/api-contract.md#errors)
OK = 'ok'
PENDING = 'pending'                    # 202: waiting for approval (Monitor / Ignore)
IGNORED = 'ignored'                    # 410: ignored in Fivenines, final
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

    @property
    def accepted(self):
        """2xx: monitored (OK) or waiting for approval (PENDING)."""
        return self.kind in (OK, PENDING)

    def __repr__(self):
        return '<Result %s status=%s message=%r>' % (self.kind, self.status, self.message)


def is_loopback(host):
    """True for localhost and loopback IP literals only.

    Parsed as an IP address, never by prefix: '127.example.com' is a DNS name
    that can resolve anywhere and must not get the plain-http exemption.
    """
    host = (host or '').strip().strip('[]').split('%', 1)[0].lower()
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
    except (TypeError, ValueError, OverflowError):  # missing, junk, inf
        return None


def classify(status, body, retry_after=None):
    message = None
    if isinstance(body, dict):
        message = body.get('message') or body.get('error')
        if message is not None:
            message = str(message)[:300]
    data = body if isinstance(body, dict) else {}
    if 200 <= status < 300:
        if data.get('state') == 'pending' or data.get('status') == 'pending':
            wait = data.get('retry_after', retry_after)
            try:
                wait = int(float(wait)) if wait is not None else PENDING_DEFAULT
            except (TypeError, ValueError, OverflowError):  # junk, inf
                wait = PENDING_DEFAULT
            return Result(PENDING, status, data, message,
                          max(PENDING_MIN, min(PENDING_MAX, wait)))
        if status == 202:
            # a 202 without the pending marker (a proxy, a queue): not an
            # acknowledgement; keep the counters and retry
            return Result(RETRY, status, data, message, retry_after)
        return Result(OK, status, data, message)
    if status == 410 and data.get('code') != 'ignored':
        # 410 Gone without the contract's marker (a retired path, a CDN): not
        # a decision of Fivenines, so never the final "ignored" state
        return Result(RETRY, status, data, message, retry_after)
    kind = {
        410: IGNORED,
        401: UNAUTHORIZED,
        402: PAYMENT_REQUIRED,
        403: FORBIDDEN,
        409: CONFLICT,
        400: REJECTED,
        413: REJECTED,
        422: REJECTED,
        429: RATE_LIMITED,
    }.get(status, RETRY)
    return Result(kind, status, data, message, retry_after)


_SURROGATE = re.compile('[\ud800-\udfff]')


def wire_text(text):
    """`text` as valid Unicode: lone surrogates (e.g. from surrogateescape-
    decoded bytes in a log message or a path) become U+FFFD; a valid pair is
    kept. json.dumps would otherwise emit escapes like \\udc80, which strict
    parsers refuse (contract s2)."""
    if not _SURROGATE.search(text):
        return text
    return text.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'replace')


def wire_safe(value):
    """A JSON-ready copy of `value` with every string (keys too) wire_text'ed.
    Anything that is not a JSON type is sent as its str()."""
    if isinstance(value, str):
        return wire_text(value)
    if isinstance(value, dict):
        return {wire_text(str(k)): wire_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [wire_safe(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return wire_text(str(value))


def encode_body(payload):
    """The bytes sent for `payload`: compact JSON, valid UTF-8, gzipped."""
    return gzip.compress(json.dumps(wire_safe(payload), separators=(',', ':')).encode('utf-8'))


class Client:
    def __init__(self, base_url, user_agent):
        self.base_url = base_url
        self.user_agent = user_agent

    def _post(self, path, token, payload):
        body = encode_body(payload)
        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json',
            'Content-Encoding': 'gzip',
            'Accept': 'application/json',
            'User-Agent': self.user_agent,
        }
        try:
            response = requests.post(
                self.base_url + path, data=body, headers=headers,
                timeout=TIMEOUT, allow_redirects=False)
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

    def enroll(self, credential, payload):
        """credential: the enrollment key, or the secret a copy presents."""
        result = self._post(ENROLL_PATH, credential, payload)
        if result.accepted and not (result.data.get('token') and result.data.get('instance_id')):
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
