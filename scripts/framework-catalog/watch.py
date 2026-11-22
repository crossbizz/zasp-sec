"""Review public upstream reference changes without changing release locks or mapping decisions."""
import base64
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from catalog import CATALOG, LOCKS, changes, enterprise

ALLOWED = {
    'mitre-atlas/atlas-data', 'mitre/cti',
    'GenAI-Security-Project/GenAI-LLM-Top10', 'GenAI-Security-Project/GenAI-Security-Corpus',
    'OWASP/www-project-top-10-for-large-language-model-applications',
}
BLOB = re.compile(r'[0-9a-f]{40}')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self):
        self.opener = build_opener(NoRedirect)
        self.cache = {}

    def get(self, repo, endpoint):
        if repo not in ALLOWED or not endpoint.startswith('/'):
            raise ValueError('unapproved upstream repository')
        key = repo, endpoint
        if key in self.cache:
            return self.cache[key]
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'zasp-framework-watch'}
        if token := os.environ.get('GITHUB_TOKEN'):
            headers['Authorization'] = 'Bearer ' + token
        request = Request('https://api.github.com/repos/' + repo + endpoint, headers=headers)
        try:
            with self.opener.open(request, timeout=12) as response:
                raw = response.read(524289)
                if len(raw) > 524288:
                    raise ValueError('upstream metadata too large')
                result = json.loads(raw)
        except HTTPError as e:
            if e.code != 404:
                raise
            result = None
        self.cache[key] = result
        return result


def contents(api, repo, path, ref):
    return api.get(repo, '/contents/' + quote(path, safe='/') + '?ref=' + quote(ref, safe=''))


def blob(item):
    if item is None:
        return None
    if not isinstance(item, dict) or item.get('type') != 'file' or not BLOB.fullmatch(item.get('sha', '')):
        raise ValueError('unrecognized metadata for a locked file')
    return item['sha']


def release_parts(lock):
    match = re.fullmatch(r'https://raw\.githubusercontent\.com/([^/]+/[^/]+)/([a-f0-9]{40})/(.+)', lock['source_url'])
    if not match or match[1] not in ALLOWED:
        raise ValueError('unknown pinned repository')
    return match.groups()


def release_tags(api, repo, prefix, pattern, edition):
    tags = api.get(repo, '/tags?per_page=100')
    if not isinstance(tags, list) or len(tags) > 100:
        raise ValueError('unavailable release tags')
    valid = [t for t in tags if re.fullmatch(pattern, t['name'])]
    if not valid:
        raise ValueError('no recognized upstream release')
    def version(tag):
        return tuple(map(int, tag.removeprefix(prefix).split('.')))
    newest = max(valid, key=lambda t: version(t['name']))
    ref = api.get(repo, '/git/ref/tags/' + quote(prefix + edition, safe=''))
    obj = ref.get('object') if ref else None
    if obj and obj['type'] == 'tag' and BLOB.fullmatch(obj['sha']):
        obj = api.get(repo, '/git/tags/' + obj['sha'])['object']
    if obj and (obj['type'] != 'commit' or not BLOB.fullmatch(obj['sha'])):
        raise ValueError('unrecognized pinned tag')
    pinned_target = obj['sha'] if obj else None
    remote = newest['commit']['sha']
    if not BLOB.fullmatch(remote):
        raise ValueError('unrecognized release commit')
    candidate = (newest['name'].removeprefix(prefix), remote) if version(newest['name']) > version(edition) else None
    return pinned_target, candidate


def metadata_subset(item, max_bytes=65536):
    if not isinstance(item, dict) or item.get('type') != 'file' or item.get('encoding') != 'base64' or not 0 < item.get('size', 0) <= max_bytes:
        raise ValueError('unsupported upstream index metadata')
    data = base64.b64decode(''.join(item['content'].split()), validate=True)
    if len(data) != item['size']:
        raise ValueError('incorrect index length')
    return data


def review(lock, api):
    repo, pinned, path = release_parts(lock)
    frame, edition = lock['framework'], lock['edition']
    default = 'master' if repo == 'mitre/cti' else 'main'
    # Query metadata rather than downloading published PDFs or large corpora.
    pinned_blob = blob(contents(api, repo, path, pinned))
    if not pinned_blob:
        raise ValueError('pinned source no longer accessible')
    active_item = contents(api, repo, path, default)
    active_blob = blob(active_item)
    result = {'framework':frame, 'edition':edition, 'pinned_source':lock['source_url'],
              'locked_sha256':lock['source_digest'], 'pinned_blob':pinned_blob, 'changes':[]}
    events = result['changes']
    if active_blob != pinned_blob:
        events.append({'change':'pinned_path_changed' if active_blob else 'pinned_path_removed',
                       'path':path, 'previous_blob':pinned_blob, 'current_blob':active_blob})
    if frame in ('mitre_atlas', 'mitre_attack_enterprise'):
        atlas = frame == 'mitre_atlas'
        prefix, pattern = ('v', r'v20\d\d\.\d\d') if atlas else ('ATT&CK-v', r'ATT&CK-v\d+\.\d+')
        target, latest = release_tags(api,repo,prefix,pattern,edition)
        if target != pinned:
            events.append({'change':'pinned_tag_moved' if target else 'pinned_tag_removed',
                           'tag':prefix+edition,'locked_commit':pinned,'current_commit':target})
        if latest:
            candidate, commit = latest
            candidate_path = path.replace('ATLAS-' + edition, 'ATLAS-' + candidate) if atlas else path
            source = contents(api,repo,candidate_path,commit)
            event = {'change':'upstream_edition_available','edition':candidate,
                     'release':'https://github.com/'+repo+'/tree/'+commit,
                     'path':candidate_path,'candidate_blob':blob(source)}
            if source and not atlas:
                old = json.loads((CATALOG / f'{frame}-{edition}.json').read_text())
                try:
                    event['control_changes'] = changes(old, {'framework':frame,'entries':enterprise(metadata_subset(source))})
                except ValueError:
                    event['control_review'] = 'Review the changed or retired scope of T1059.'
            else:
                event['control_review'] = 'Review the published inventory, including removals, mitigation classes and ID reassignments.'
            events.append(event)
    elif frame == 'owasp_agentic_top10':
        directory = 'corpus/agentic-top10'
        items = contents(api,repo,directory,default)
        if not isinstance(items,list):
            raise ValueError('missing Agentic publication directory')
        for row in items:
            match = re.fullmatch(r'(20\d\d)-final',row['name'])
            if row['type']=='dir' and match and match[1]>edition:
                events.append({'change':'final_edition_directory_added','edition':match[1],
                               'source':'https://github.com/'+repo+'/tree/'+default+'/'+directory+'/'+row['name']})
    elif edition == '2026':
        roots = contents(api,repo,'',default)
        if not isinstance(roots,list):
            raise ValueError('missing LLM publication directory')
        for row in roots:
            year=row['name']
            if row['type']!='dir' or not re.fullmatch(r'20\d\d',year) or year <= edition:
                continue
            event={'change':'edition_directory_added','edition':year,
                   'source':'https://github.com/'+repo+'/tree/'+default+'/'+year}
            # A working directory may precede publication. Only public index
            # headings are compared and a human must confirm publication.
            item=contents(api,repo,year+'/README.md',default)
            if item:
                text=metadata_subset(item).decode()
                headings=re.findall(r'^\| (LLM\d\d):'+year+r' ([^|\r\n]{1,128}?) \| ',text,re.M)
                if [ident for ident,_ in headings]==[f'LLM{i:02d}' for i in range(1,11)]:
                    previous=json.loads((CATALOG/f'{frame}-{edition}.json').read_text())
                    event['control_changes']=changes(previous,{'framework':frame,'entries':[{'id':ident,'title':title,'kind':'risk'} for ident,title in headings]})
            events.append(event)
    result['status']='review_required' if events else 'unchanged'
    return result


def scan(locks,api):
    rows=[]
    for lock in locks:
        try:
            rows.append(review(lock,api))
        except (ValueError, TypeError, KeyError, OSError) as err:
            rows.append({'framework':lock['framework'],'edition':lock['edition'],'status':'unavailable',
                         'changes':[], 'reason':type(err).__name__,'pinned_source':lock['source_url']})
    return rows


def main(directory):
    rows=scan(json.loads(LOCKS.read_text()),GitHub())
    directory.mkdir(parents=True,exist_ok=True)
    stamp=dt.datetime.now(dt.timezone.utc).isoformat()
    with (directory/'framework-review.json').open('x') as out:
        json.dump({'schema':'framework-upstream-review.v1','observed_at':stamp,'reviews':rows},out,indent=2)
        out.write('\n')
    lines=['# Framework reference review','',f'Checked at {stamp}. The reviewed catalog remains pinned.','',
           '| Framework | Pinned edition | Result | Changes |','|---|---|---|---|']
    for row in rows:
        lines.append(f"| {row['framework']} | {row['edition']} | {row['status']} | {len(row['changes'])} |")
        for change in row['changes']:
            edition=change.get('edition',row['edition'])
            lines.append(f"| | {edition} | {change['change']} | See the upstream paths and identifiers in the JSON artifact. |")
    with (directory/'summary.md').open('x') as out:
        out.write('\n'.join(lines)+'\n')
    return int(any(r['status']=='unavailable' for r in rows))


if __name__=='__main__':
    if len(sys.argv)!=2:
        sys.exit('Usage: watch.py NEW_OUTPUT_DIR')
    sys.exit(main(Path(sys.argv[1])))
