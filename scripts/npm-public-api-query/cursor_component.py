"""Offline verifier for a ROOT-owned official GitHub npm API page acquisition.

No network, credentials, package inventory, process launcher, or clearance here.
The injected acquisition function must independently enforce current tool/source
pins, TLS/proxy policy, original request deadlines, and normal child joins.
"""
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

KINDS = ('reviewed', 'unreviewed', 'malware')
LIMITS = dict(response=20 << 20, aggregate=128 << 20, requests=256,
              members=300000, advisory=1 << 20)
GHSA = re.compile(r'GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\Z')


class Refused(ValueError):
    """A fixed public diagnostic; never render upstream bodies or caught errors."""


def refuse():
    raise Refused('public npm cursor component refused')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_json(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > LIMITS['response']:
        refuse()
    # Bound nesting before the JSON decoder allocates nested objects. JSON's
    # grammar and escaped-string correctness are still checked by the decoder.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                refuse()
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                refuse()

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                refuse()
            out[key] = value
        return out

    try:
        return json.loads(raw.decode('utf-8', errors='strict'),
                          object_pairs_hook=pairs,
                          parse_constant=lambda _: refuse())
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        refuse()


def endpoint(kind, cursor=None):
    if kind not in KINDS:
        refuse()
    values = [('ecosystem', 'npm'), ('type', kind), ('per_page', '100'),
              ('sort', 'updated'), ('direction', 'asc')]
    if cursor is not None:
        if not isinstance(cursor, str) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{1,4096}', cursor):
            refuse()
        values.append(('after', cursor))
    return '/advisories?' + urlencode(values)


def next_endpoint(link, kind):
    if not isinstance(link, str) or len(link) > 16384 or '\r' in link or '\n' in link:
        refuse()
    nexts = []
    for part in link.split(',') if link else []:
        m = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*', part)
        if not m:
            refuse()
        u = urlsplit(m[1])
        if u.scheme != 'https' or u.netloc != 'api.github.com' or u.path != '/advisories' or u.fragment:
            refuse()
        try:
            query = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            refuse()
        q = dict(query)
        if len(q) != len(query):
            refuse()
        fixed = dict(ecosystem='npm', type=kind, per_page='100', sort='updated', direction='asc')
        if any(q.get(k) != v for k, v in fixed.items()) or set(q) - set(fixed) - {'after', 'before'}:
            refuse()
        if 'after' in q and 'before' in q:
            refuse()
        for key in ('before', 'after'):
            if key in q and not re.fullmatch(r'[A-Za-z0-9+/=_-]{1,4096}', q[key]):
                refuse()
        if m[2] == 'next':
            if 'after' not in q:
                refuse()
            nexts.append(endpoint(kind, q['after']))
    if len(nexts) > 1:
        refuse()
    return nexts[0] if nexts else None


def collect(acquire, guard):
    """Acquire all three type streams without package/withdrawal/severity filters.

    acquire(endpoint, maximum_total_http_bytes) returns (status, headers, body,
    total_http_bytes). ROOT separately retains exact raw pages and authenticates
    the fixed public origin. Supplied callback data alone is not that authority.
    Every page is charged before parsing or record retention.
    """
    pages, rows, streams, seen_ids, seen_urls = [], [], [], set(), set()
    total = requests = 0
    for kind in KINDS:
        target = endpoint(kind)
        stream_count = 0
        while target is not None:
            guard()
            if requests >= LIMITS['requests'] or total >= LIMITS['aggregate'] or target in seen_urls:
                refuse()
            seen_urls.add(target)
            allowance = min(LIMITS['response'], LIMITS['aggregate'] - total)
            status, headers, body, wire_bytes = acquire(target, allowance)
            guard()
            if not isinstance(body, bytes) or type(wire_bytes) is not int or wire_bytes < len(body) or wire_bytes > allowance:
                refuse()
            requests += 1
            total += wire_bytes
            if status != 200 or not isinstance(headers, list) or len(headers) > 256:
                refuse()
            selected = {}
            header_bytes = 0
            for key, value in headers:
                if not isinstance(key, str) or not isinstance(value, str):
                    refuse()
                header_bytes += len(key.encode()) + len(value.encode())
                if header_bytes > 65536:
                    refuse()
                key = key.lower()
                if key in ('link', 'content-type'):
                    if key in selected:
                        refuse()
                    selected[key] = value
            if selected.get('content-type', '').split(';')[0].strip() != 'application/json':
                refuse()
            data = exact_json(body)
            if not isinstance(data, list) or len(data) > 100:
                refuse()
            following = next_endpoint(selected.get('link', ''), kind)
            if following is not None and not data:
                refuse()
            if len(rows) + len(data) > LIMITS['members']:
                refuse()
            for row in data:
                guard()
                if not isinstance(row, dict) or not isinstance(row.get('ghsa_id'), str) or not GHSA.fullmatch(row['ghsa_id']) or row.get('type') != kind or row['ghsa_id'] in seen_ids:
                    refuse()
                vulnerabilities = row.get('vulnerabilities')
                if not isinstance(vulnerabilities, list) or not any(isinstance(v, dict) and isinstance(v.get('package'), dict) and v['package'].get('ecosystem') == 'npm' for v in vulnerabilities):
                    refuse()
                # This is a semantic document fingerprint, not original row
                # bytes or an OSV translation. Full original page hash is bound.
                canonical = json.dumps(row, sort_keys=True, ensure_ascii=True,
                                       separators=(',', ':'), allow_nan=False).encode()
                if len(canonical) > LIMITS['advisory']:
                    refuse()
                seen_ids.add(row['ghsa_id'])
                rows.append(dict(id=row['ghsa_id'], type=kind,
                                 semanticSHA256=digest(canonical),
                                 pageBodySHA256=digest(body)))
                stream_count += 1
            pages.append(dict(endpoint=target, bodySHA256=digest(body),
                              bodyBytes=len(body), wireBytes=wire_bytes,
                              rows=len(data), nextEndpoint=following))
            target = following
        streams.append(dict(type=kind, rows=stream_count, terminalPageObserved=True))
    guard()
    return dict(format='github-npm-global-advisory-api-enumeration-component-v1',
                streams=streams, pages=pages, rows=rows, wireBytes=total,
                requests=requests, apiTraversalComplete=True,
                immutableSnapshot=False, authenticatedUpstream=False,
                osvTranslation=False, vulnerabilityMatching=False,
                releaseAccepted=False)
