#!/usr/bin/env python3
# Part of Fivenines Monitoring. License LGPL-3.
"""A stub of the Fivenines Odoo API (docs/api-contract.md), standard library only.

Used by the module's tests (in-process, random port) and for end-to-end checks:

    python3 stub_server.py --port 8899 --enrollment-key <64 hex chars> [--log-file pushes.jsonl]

Then point the module at it: fivenines_api_url = http://127.0.0.1:8899

Contract endpoints:
    POST /odoo/v1/enroll    Authorization: Bearer <enrollment key>
    POST /odoo/v1/collect   Authorization: Bearer <instance token>

Test-only endpoints (loopback clients only, never part of the contract):
    GET  /_stub/state                  instances and last payloads (no secret)
    POST /_stub/revoke   {"instance_id": "..."}     revoke one instance token
    POST /_stub/revoke_key {"key": "..."}           revoke an enrollment key
    POST /_stub/fail     {"status": 503, "count": 2, "path": "collect"}
    POST /_stub/reset
"""

import argparse
import gzip
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(HERE, 'schemas')
CONFLICT_WINDOW = 900  # seconds: two live places within 15 min = conflict
MAX_BODY = 2 * 1024 * 1024


# ---------------------------------------------------------------------------
# a minimal JSON Schema validator (the subset our schemas use)
# ---------------------------------------------------------------------------
_TYPES = {
    'object': dict, 'array': list, 'string': str, 'boolean': bool,
    'integer': int, 'number': (int, float), 'null': type(None),
}


def validate(value, schema, path='$'):
    """List of error strings (empty = valid)."""
    errors = []
    types = schema.get('type')
    if types:
        types = types if isinstance(types, list) else [types]
        ok = False
        for t in types:
            py = _TYPES[t]
            if isinstance(value, bool) and t in ('integer', 'number'):
                continue
            if isinstance(value, py):
                ok = True
                break
        if not ok:
            return ['%s: expected %s, got %s' % (path, '/'.join(types), type(value).__name__)]
    if 'enum' in schema and value not in schema['enum']:
        errors.append('%s: %r not in %r' % (path, value, schema['enum']))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in schema and value < schema['minimum']:
            errors.append('%s: %r < minimum %r' % (path, value, schema['minimum']))
        if 'maximum' in schema and value > schema['maximum']:
            errors.append('%s: %r > maximum %r' % (path, value, schema['maximum']))
    if isinstance(value, str) and 'maxLength' in schema and len(value) > schema['maxLength']:
        errors.append('%s: longer than %d' % (path, schema['maxLength']))
    if isinstance(value, dict):
        for key in schema.get('required', []):
            if key not in value:
                errors.append('%s: missing %r' % (path, key))
        props = schema.get('properties', {})
        for key, sub in props.items():
            if key in value:
                errors.extend(validate(value[key], sub, '%s.%s' % (path, key)))
        extra = schema.get('additionalProperties', True)
        if isinstance(extra, dict):
            for key, v in value.items():
                if key not in props:
                    errors.extend(validate(v, extra, '%s.%s' % (path, key)))
        elif extra is False:
            for key in value:
                if key not in props:
                    errors.append('%s: unexpected %r' % (path, key))
    if isinstance(value, list):
        if 'maxItems' in schema and len(value) > schema['maxItems']:
            errors.append('%s: more than %d items' % (path, schema['maxItems']))
        if 'items' in schema:
            for i, item in enumerate(value):
                errors.extend(validate(item, schema['items'], '%s[%d]' % (path, i)))
    return errors


def load_schema(name):
    try:
        with open(os.path.join(SCHEMA_DIR, name)) as f:
            return json.load(f)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
class StubState:
    def __init__(self, enrollment_keys=(), log_file=None):
        self.lock = threading.Lock()
        self.enrollment_keys = {k: {'revoked': False} for k in enrollment_keys}
        self.instances = {}      # instance_id -> dict
        self.tokens = {}         # token -> instance_id
        self.pushes = []         # accepted payloads (all instances)
        self.requests = []       # (path, status, instance_id) log
        self.failures = []       # injected failures
        self.log_file = log_file
        self.enroll_schema = load_schema('enroll_request.schema.json')
        self.push_schema = load_schema('push_payload.schema.json')
        self.schema_errors = []

    def public(self):
        with self.lock:
            return {
                'instances': [
                    {k: v for k, v in inst.items() if k != 'token'}
                    for inst in self.instances.values()
                ],
                'push_count': len(self.pushes),
                'requests': list(self.requests[-200:]),
                'schema_errors': list(self.schema_errors[-50:]),
                'last_pushes': self.pushes[-5:],
            }


def _bearer(headers):
    value = headers.get('Authorization') or ''
    parts = value.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = 'FiveninesStub/1'
    state = None  # set on the subclass made by make_server()

    def log_message(self, fmt, *args):  # one short line, never a header
        if self.server.verbose:
            sys.stderr.write('stub: %s %s\n' % (self.address_string(), fmt % args))

    # -- helpers -------------------------------------------------------
    def _send(self, status, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length > MAX_BODY:
            return None, 413
        raw = self.rfile.read(length) if length else b''
        if self.headers.get('Content-Encoding') == 'gzip':
            try:
                raw = gzip.decompress(raw)
            except OSError:
                return None, 400
            if len(raw) > MAX_BODY:
                return None, 413
        try:
            return json.loads(raw or b'{}'), None
        except ValueError:
            return None, 400

    def _injected(self, path):
        st = self.state
        with st.lock:
            for f in st.failures:
                if f['count'] > 0 and f.get('path') in (None, path):
                    f['count'] -= 1
                    return f
        return None

    def _record(self, path, status, instance_id=None):
        with self.state.lock:
            self.state.requests.append({'at': time.time(), 'path': path, 'status': status,
                                        'instance_id': instance_id})

    # -- routing -------------------------------------------------------
    def do_GET(self):
        if self.path == '/_stub/state' and self._loopback():
            return self._send(200, self.state.public())
        self._send(404, {'status': 'error', 'message': 'not found'})

    def do_POST(self):
        if self.path.startswith('/_stub/'):
            return self._admin()
        if self.path == '/odoo/v1/enroll':
            return self._enroll()
        if self.path == '/odoo/v1/collect':
            return self._collect()
        self._send(404, {'status': 'error', 'message': 'not found'})

    def _loopback(self):
        return self.client_address[0] in ('127.0.0.1', '::1')

    def _admin(self):
        if not self._loopback():
            return self._send(403, {'status': 'error', 'message': 'loopback only'})
        body, err = self._body()
        body = body or {}
        st = self.state
        with st.lock:
            if self.path == '/_stub/revoke':
                inst = st.instances.get(str(body.get('instance_id')))
                if not inst:
                    return self._send(404, {'status': 'error', 'message': 'no such instance'})
                inst['revoked'] = True
            elif self.path == '/_stub/revoke_key':
                if body.get('key') in st.enrollment_keys:
                    st.enrollment_keys[body['key']]['revoked'] = True
            elif self.path == '/_stub/add_key':
                st.enrollment_keys[body['key']] = {'revoked': False}
            elif self.path == '/_stub/fail':
                st.failures.append({'status': int(body.get('status', 503)),
                                    'count': int(body.get('count', 1)),
                                    'path': body.get('path'),
                                    'retry_after': body.get('retry_after'),
                                    'delay': float(body.get('delay', 0))})
            elif self.path == '/_stub/reset':
                st.instances.clear()
                st.tokens.clear()
                st.pushes.clear()
                st.requests.clear()
                st.failures.clear()
                st.schema_errors.clear()
            else:
                return self._send(404, {'status': 'error', 'message': 'not found'})
        self._send(200, {'status': 'ok'})

    def _maybe_fail(self, path):
        f = self._injected(path)
        if not f:
            return False
        if f.get('delay'):
            time.sleep(f['delay'])
        headers = {'Retry-After': str(f['retry_after'])} if f.get('retry_after') else None
        self._record(path, f['status'])
        self._send(f['status'], {'status': 'error', 'message': 'injected failure'}, headers)
        return True

    def _enroll(self):
        if self._maybe_fail('enroll'):
            return
        st = self.state
        key = _bearer(self.headers)
        body, err = self._body()
        if err:
            self._record('enroll', err)
            return self._send(err, {'status': 'error', 'message': 'invalid body'})
        with st.lock:
            entry = st.enrollment_keys.get(key)
            if not entry or entry['revoked']:
                status = 401
            else:
                status = None
        if status:
            self._record('enroll', 401)
            return self._send(401, {'status': 'error', 'message': 'Invalid enrollment key'})
        errors = validate(body, st.enroll_schema) if st.enroll_schema else []
        if errors:
            with st.lock:
                st.schema_errors.append({'path': 'enroll', 'errors': errors[:20]})
            self._record('enroll', 422)
            return self._send(422, {'status': 'error', 'message': 'invalid payload',
                                    'errors': errors[:20]})
        inst = body['instance']
        with st.lock:
            instance_id = 'odi_%s' % secrets.token_hex(6)
            token = secrets.token_hex(32)
            st.instances[instance_id] = {
                'instance_id': instance_id,
                'token': token,
                'fingerprint': inst['fingerprint'],
                'fingerprint_components': inst.get('fingerprint_components'),
                'name': '%s (%s)' % (inst.get('database'), inst.get('base_url')),
                'reason': body.get('reason'),
                'previous_instance_id': body.get('previous_instance_id'),
                'enrolled_at': time.time(),
                'revoked': False,
                'last_push_at': None,
                'last_fingerprint_push_at': None,
                'push_count': 0,
                'last_payload': None,
            }
            st.tokens[token] = instance_id
        self._record('enroll', 201, instance_id)
        self._send(201, {'status': 'ok', 'instance_id': instance_id, 'token': token,
                         'name': st.instances[instance_id]['name']})

    def _collect(self):
        if self._maybe_fail('collect'):
            return
        st = self.state
        token = _bearer(self.headers)
        body, err = self._body()
        with st.lock:
            instance_id = st.tokens.get(token)
            inst = st.instances.get(instance_id)
        if not inst or inst['revoked']:
            self._record('collect', 401, instance_id)
            return self._send(401, {'status': 'error', 'message': 'Invalid instance token'})
        if err:
            self._record('collect', err, instance_id)
            return self._send(err, {'status': 'error', 'message': 'invalid body'})
        errors = validate(body, st.push_schema) if st.push_schema else []
        if errors:
            with st.lock:
                st.schema_errors.append({'path': 'collect', 'errors': errors[:20]})
            self._record('collect', 422, instance_id)
            return self._send(422, {'status': 'error', 'message': 'invalid payload',
                                    'errors': errors[:20]})
        now = time.time()
        fingerprint = body['instance']['fingerprint']
        process = body.get('process') or {}
        identity = (body['instance'].get('hostname'), process.get('pid'), process.get('started_at'))
        with st.lock:
            status = None
            if fingerprint != inst['fingerprint']:
                # contract s5: the same running server changed its URL -> adopt;
                # another place while the old one pushed < 15 min ago -> 409;
                # the old place silent for 15 min -> a move, adopt
                same_process = identity == inst.get('last_identity')
                live = inst['last_fingerprint_push_at'] and now - inst['last_fingerprint_push_at'] < CONFLICT_WINDOW
                if live and not same_process:
                    status = 409
                else:
                    inst['fingerprint'] = fingerprint
            if status is None:
                inst['last_identity'] = identity
                inst['last_fingerprint_push_at'] = now
                inst['last_push_at'] = now
                inst['push_count'] += 1
                inst['last_payload'] = body
                st.pushes.append({'instance_id': instance_id, 'received_at': now, 'payload': body})
                if len(st.pushes) > 500:
                    del st.pushes[:100]
        if status == 409:
            self._record('collect', 409, instance_id)
            return self._send(409, {'status': 'error',
                                    'message': 'This secret is in use from another location'})
        if st.log_file:
            with open(st.log_file, 'a') as f:
                f.write(json.dumps({'instance_id': instance_id, 'received_at': now,
                                    'payload': body}) + '\n')
        self._record('collect', 200, instance_id)
        self._send(200, {'status': 'ok'})


class StubServer:
    """In-process stub for tests: StubServer(keys).start(); .url; .stop()."""

    def __init__(self, enrollment_keys=(), host='127.0.0.1', port=0, log_file=None, verbose=False):
        self.state = StubState(enrollment_keys, log_file)
        handler = type('BoundHandler', (Handler,), {'state': self.state})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.httpd.verbose = verbose
        self.thread = None

    @property
    def url(self):
        host, port = self.httpd.server_address[:2]
        return 'http://%s:%d' % (host, port)

    def start(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8899)
    parser.add_argument('--enrollment-key', action='append', default=[],
                        help='accepted enrollment key (repeatable); also FIVENINES_STUB_KEYS (comma separated)')
    parser.add_argument('--log-file', help='append every accepted payload to this JSONL file')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args(argv)
    keys = list(args.enrollment_key) + [
        k for k in os.environ.get('FIVENINES_STUB_KEYS', '').split(',') if k]
    if not keys:
        parser.error('at least one --enrollment-key is required')
    stub = StubServer(keys, args.host, args.port, args.log_file, verbose=not args.quiet)
    sys.stderr.write('Fivenines stub listening on %s (%d enrollment key(s))\n' % (stub.url, len(keys)))
    try:
        stub.httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
