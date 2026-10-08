"""Versioned public-lock-only official upstream query adapter; no network.

ROOT must authenticate the documented public API, retain full HTTP originals,
and bind the issued public lock observation/tool/source pins externally.
"""
import base64
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from cursor_component import collect, exact_json, Refused, LIMITS

PUBLIC_COMMIT='fcd4a52293434d962e04aa6428cb4e4c4afe5d28'
PUBLIC_LOCK_SHA256='0e8b7fa1332878386816dd73ba0118fb8dfc8a414b7912f90e95f2dda8bae51c'


def refuse():raise Refused('public npm query adapter refused')


def canonical_version(v):
    if not isinstance(v,str) or len(v)>256:return False
    m=re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?',v)
    if not m:return False
    for field in (m[4],m[5]):
        if field is not None and any(not x for x in field.split('.')):return False
    if m[4] is not None and any(x.isdigit() and len(x)>1 and x[0]=='0' for x in m[4].split('.')):return False
    return all(int(n)<=9007199254740991 for n in m.group(1,2,3))


def public_inventory(raw):
    if not isinstance(raw,bytes) or len(raw)>(4<<20) or hashlib.sha256(raw).hexdigest()!=PUBLIC_LOCK_SHA256:refuse()
    # The original strict parser rejects duplicate/UTF8/trailing/depth errors.
    lock=exact_json(raw)
    if lock.get('lockfileVersion')!=3 or not isinstance(lock.get('packages'),dict) or '' not in lock['packages']:refuse()
    rows=[]
    for location,p in lock['packages'].items():
        if not isinstance(p,dict) or location.startswith('/') or '..' in location or '\\' in location:refuse()
        if not location or 'node_modules/' not in location or p.get('dev') is True:continue
        if p.get('link') is True:refuse()
        name=p.get('name',location.rsplit('node_modules/',1)[1])
        if not isinstance(name,str) or len(name)>214 or len(location)>4096 or not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+',name) or not canonical_version(p.get('version')):refuse()
        integrity=p.get('integrity')
        if not isinstance(integrity,str) or not re.fullmatch(r'sha512-[A-Za-z0-9+/]+={0,2}',integrity):refuse()
        try:
            if len(base64.b64decode(integrity[7:],validate=True))!=64:refuse()
        except ValueError:refuse()
        resolved=p.get('resolved')
        if not isinstance(resolved,str):refuse()
        u=urlsplit(resolved)
        if u.scheme!='https' or u.netloc!='registry.npmjs.org' or u.query or u.fragment:refuse()
        rows.append(dict(location=location,name=name,version=p['version'],integrity=integrity,resolved=resolved))
    if not rows or len(rows)>10000:refuse()
    return sorted(rows,key=lambda row:row['location'])


def groups_for(inventory):
    pairs=sorted({(r['name'],r['version']) for r in inventory})
    groups=[]
    for i in range(0,len(pairs),10):
        group=[name+'@'+version for name,version in pairs[i:i+10]]
        if len(','.join(group).encode())>4096:refuse()
        groups.append(group)
    return groups


def scope_endpoint(target,affects):
    u=urlsplit(target)
    if u.scheme or u.netloc or u.path!='/advisories' or u.fragment:refuse()
    pairs=parse_qsl(u.query,strict_parsing=True)
    if any(k=='affects' for k,v in pairs):refuse()
    result='/advisories?'+urlencode(pairs+[('affects',affects)])
    if len(result)>8192:refuse()
    return result


def normalize_link(link,affects):
    # Verify the query binding BEFORE removing it for the original closed
    # cursor verifier. Original raw HTTP headers remain external evidence.
    if not isinstance(link,str) or len(link)>16384 or '\r' in link or '\n' in link:refuse()
    result=[]
    for part in link.split(',') if link else []:
        m=re.fullmatch(r'\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*',part)
        if not m:refuse()
        u=urlsplit(m[1]);pairs=parse_qsl(u.query,keep_blank_values=True,strict_parsing=True)
        if [v for k,v in pairs if k=='affects']!=[affects]:refuse()
        stripped=[(k,v) for k,v in pairs if k!='affects']
        result.append('<'+urlunsplit((u.scheme,u.netloc,u.path,urlencode(stripped),u.fragment))+'>; rel="'+m[2]+'"')
    return ', '.join(result)


def collect_public_lock(raw_lock,acquire,guard):
    inventory=public_inventory(raw_lock)
    groups=groups_for(inventory)
    requests=wire_bytes=0
    coverage=[];pages=[];observations={}
    for number,group in enumerate(groups):
        guard();affects=','.join(group)
        def scoped_acquire(target,allowance):
            nonlocal requests,wire_bytes
            guard()
            if requests>=LIMITS['requests'] or wire_bytes>=LIMITS['aggregate']:refuse()
            allowance=min(allowance,LIMITS['aggregate']-wire_bytes)
            status,headers,body,size=acquire(scope_endpoint(target,affects),allowance)
            guard()
            if not isinstance(body,bytes) or not isinstance(headers,list) or len(headers)>256 or type(size) is not int or size<len(body) or size>allowance:refuse()
            requests+=1;wire_bytes+=size
            header_bytes=0
            for key,value in headers:
                if not isinstance(key,str) or not isinstance(value,str):refuse()
                header_bytes+=len(key.encode())+len(value.encode())
                if header_bytes>65536 or (key.lower()=='link' and (len(value)>16384 or '\r' in value or '\n' in value)):refuse()
            transformed=[]
            for key,value in headers:
                transformed.append((key,normalize_link(value,affects) if key.lower()=='link' else value))
            return status,transformed,body,size
        result=collect(scoped_acquire,guard)
        for page in result['pages']:
            page=dict(page,endpoint=scope_endpoint(page['endpoint'],affects),group=number)
            if page['nextEndpoint'] is not None:page['nextEndpoint']=scope_endpoint(page['nextEndpoint'],affects)
            pages.append(page)
        for row in result['rows']:
            old=observations.get(row['id'])
            if old is not None:
                if old['semanticSHA256']!=row['semanticSHA256'] or old['type']!=row['type']:refuse()
                old['queryGroups'].append(number)
            else:observations[row['id']]=dict(row,queryGroups=[number])
        coverage.append(dict(group=number,publicPackageVersions=group,streams=result['streams']))
    guard()
    return dict(format='official-public-lock-npm-advisory-query-component-v1',
                publicSource=dict(repository='https://github.com/crossbizz/zasp-sec',commit=PUBLIC_COMMIT,lockSHA256=PUBLIC_LOCK_SHA256),
                inventory=inventory,coverage=coverage,pages=pages,
                upstreamMatchedObservations=sorted(observations.values(),key=lambda r:r['id']),
                requests=requests,wireBytes=wire_bytes,
                allIssuedPublicLockQueriesTraversed=True,
                matchingAuthority='Documented upstream affects=package@version filter; local range matching is not asserted.',
                immutableSnapshot=False,authenticatedUpstream=False,
                fullUnrelatedMalwareCorpus=False,osvTranslation=False,
                goFullMVS=False,images=False,physicalSBOM=False,releaseAccepted=False)
