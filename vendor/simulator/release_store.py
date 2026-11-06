"""Virtual Lab data-only releases. No Git, root, package or shell execution on clients."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import uuid
import zipfile

SCHEMA = 1
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILES = 1000
REQUIRED = {'LICENSE', 'renode/scripts/platform.resc', 'renode/platforms/stm32f446re.repl',
            'bridge/renode_bridge.py', 'bridge/protocol.py', 'gui/app.py', 'gui/index.html',
            'gui/static/app.js', 'gui/static/style.css', 'examples/adc-led-v1/main.c'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def parse(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('DuplicateJSONKey')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def hash_id(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('InvalidReleaseHash')
    return value


def plain(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.is_symlink() or (item.exists() and getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('LinkedPathRejected')
    return path


def relative(name):
    if (not isinstance(name, str) or not name or '\\' in name or ':' in name or
            any(ord(c) < 32 for c in name) or name.startswith('/') or
            any(p in ('', '.', '..') or p.endswith((' ', '.')) or p.lower() == '.git' for p in name.split('/'))):
        raise ValueError('UnsafeArchivePath')
    # Also avoid Windows device names, case collisions, and ADS on shared stores.
    if any(re.fullmatch(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?', p) for p in name.split('/')):
        raise ValueError('UnsafeArchivePath')
    return name


def manifest(raw, expected, test_only=False):
    if len(raw) > 1024 * 1024 or sha(raw) != hash_id(expected):
        raise ValueError('ManifestHashMismatch')
    m = parse(raw)
    if set(m) != {'schema', 'product', 'commit', 'status', 'compatibility', 'archive', 'files'}:
        raise ValueError('ManifestSchemaRejected')
    if (m['schema'] != SCHEMA or m['product'] != 'stm32-renode-virtual-lab' or
            not isinstance(m['commit'], str) or not re.fullmatch('[0-9a-f]{40}', m['commit'])):
        raise ValueError('ManifestIdentityRejected')
    if m['status'] not in ('Approved', 'TestOnly') or (m['status'] == 'TestOnly' and not test_only):
        raise ValueError('TestOnlyNotAllowed')
    c = m['compatibility']
    if (set(c) != {'adapterApi', 'bridgeApi', 'profiles', 'renodeVersions'} or c['adapterApi'] != 1 or
            c['bridgeApi'] != 'virtual-lab-http-v1' or c['profiles'] != ['adc-led-v1'] or
            not isinstance(c['renodeVersions'], list) or not c['renodeVersions'] or
            any(v not in ('1.16.0', '1.17.0') for v in c['renodeVersions'])):
        raise ValueError('IncompatibleRelease')
    a = m['archive']
    if set(a) != {'url', 'sha256', 'size'} or type(a['size']) is not int or not 0 < a['size'] <= MAX_ARCHIVE:
        raise ValueError('InvalidArchiveRecord')
    hash_id(a['sha256'])
    https_url(a['url'])
    if not isinstance(m['files'], dict) or not REQUIRED.issubset(m['files']) or not len(m['files']) <= MAX_FILES:
        raise ValueError('RequiredProductFilesMissing')
    seen = set()
    total = 0
    for name, record in m['files'].items():
        relative(name)
        key = name.casefold()
        if key in seen or set(record) != {'sha256', 'size'} or type(record['size']) is not int or record['size'] < 0:
            raise ValueError('InvalidFileRecord')
        seen.add(key)
        hash_id(record['sha256'])
        total += record['size']
    if total > MAX_ARCHIVE:
        raise ValueError('ExpandedSizeExceeded')
    return m


def https_url(url):
    from urllib.parse import urlsplit
    if not isinstance(url, str) or any(ord(c) < 33 for c in url):
        raise ValueError('HTTPSRequired')
    u = urlsplit(url)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError('HTTPSRequired')
    return url


def download(url, limit):
    import urllib.request
    class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            https_url(newurl)
            return super().redirect_request(request, fp, code, message, headers, newurl)
    opener = urllib.request.build_opener(HTTPSRedirect())
    with opener.open(https_url(url), timeout=30) as response:
        https_url(response.geturl())
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('DownloadSizeExceeded')
    return raw


def archive_files(archive, m):
    archive = plain(archive)
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError('ArchiveSizeExceeded')
    raw = archive.read_bytes()
    if len(raw) != m['archive']['size'] or sha(raw) != m['archive']['sha256']:
        raise ValueError('ArchiveHashMismatch')
    import io
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        if len(z.infolist()) != len(m['files']):
            raise ValueError('ArchiveFileSetMismatch')
        for info in z.infolist():
            name = relative(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if (name in result or name not in m['files'] or info.is_dir() or mode not in (0, 0o100000) or
                    info.flag_bits & 1 or info.file_size != m['files'][name]['size']):
                raise ValueError('UnsafeArchiveMember')
            data = z.read(info)
            if sha(data) != m['files'][name]['sha256']:
                raise ValueError('ProductFileHashMismatch')
            result[name] = data
    return result


def verify_tree(product, m):
    found = set()
    for p in plain(product).rglob('*'):
        plain(p)
        if p.is_file():
            name = p.relative_to(product).as_posix()
            found.add(name)
            record = m['files'].get(name)
            data = p.read_bytes()
            if record is None or len(data) != record['size'] or sha(data) != record['sha256']:
                raise ValueError('InstalledProductMismatch')
        elif not p.is_dir():
            raise ValueError('SpecialFileRejected')
    if found != set(m['files']):
        raise ValueError('InstalledFileSetMismatch')


def atomic_json(path, value):
    path = plain(path)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
    with temp.open('xb') as f:
        f.write(encoded(value))
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


@contextlib.contextmanager
def file_lock(path):
    path = plain(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as f:
        if os.name == 'nt':
            import msvcrt
            f.seek(0, 2)
            if f.tell() == 0:
                f.write(b'\0')
                f.flush()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == 'nt':
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f, fcntl.LOCK_UN)


def user_root():
    return Path.home() / '.local/share/lab-virtual-lab'


def session_lock():
    return Path.home() / '.local/state/lab-simulator/session.lock'


class Store:
    def __init__(self, root, approved, test_only=False):
        self.root = plain(root)
        self.approved = {hash_id(h) for h in approved}
        self.test_only = test_only

    def installed(self, identity, verify_files=True):
        identity = hash_id(identity)
        if identity not in self.approved:
            raise ValueError('ReleaseNotCentrallyApproved')
        folder = plain(self.root / 'releases' / identity)
        m = manifest(plain(folder / 'manifest.json').read_bytes(), identity, self.test_only)
        if verify_files:
            verify_tree(folder / 'product', m)
        return folder / 'product', m

    def state(self):
        if self.root.exists():
            marker = plain(self.root / 'store.json')
            if not marker.is_file() or parse(marker.read_bytes()) != {'schema': 1, 'product': 'lab-virtual-lab-store'}:
                raise ValueError('UnmanagedExistingUserRoot')
        path = plain(self.root / 'active.json')
        if not path.exists():
            return None
        s = parse(path.read_bytes())
        if set(s) != {'schema', 'current', 'previous'} or s['schema'] != 1:
            raise ValueError('InvalidUserState')
        hash_id(s['current'])
        if s['previous'] is not None:
            hash_id(s['previous'])
        return s

    def selected(self, verify_files=True):
        s = self.state()
        if s is None:
            raise ValueError('VirtualLabPreparationRequired')
        product, m = self.installed(s['current'], verify_files=verify_files)
        return product, m, s

    def apply(self, mode, identity, raw=None, archive=None, runtime=None):
        """Caller holds the same session lock as Renode for the whole transaction."""
        if mode not in ('prepare', 'update', 'rollback'):
            raise ValueError('UnknownUpdateMode')
        old = self.state()
        if old is not None and mode != 'rollback':
            self.installed(old['current'])  # Never silently repair a modified current release.
        if mode == 'prepare' and old and old['current'] != identity:
            raise ValueError('ExistingUserUseUpdate')
        if mode in ('update', 'rollback') and old is None:
            raise ValueError('VirtualLabPreparationRequired')
        if mode == 'rollback':
            identity = identity or old['previous']
            if identity is None or identity == old['current']:
                raise ValueError('NoRollbackTarget')
        hash_id(identity)
        if identity not in self.approved:
            raise ValueError('ReleaseNotCentrallyApproved')
        target = plain(self.root / 'releases' / identity)
        if target.exists():
            product, m = self.installed(identity)
        elif mode == 'rollback':
            raise ValueError('RollbackTargetNotInstalled')
        else:
            m = manifest(raw, identity, self.test_only)
            if runtime not in m['compatibility']['renodeVersions']:
                raise ValueError('RenodeVersionMismatch')
            files = archive_files(archive, m)
            if not self.root.exists():
                self.root.mkdir(parents=True, mode=0o700)
                atomic_json(self.root / 'store.json', {'schema': 1, 'product': 'lab-virtual-lab-store'})
            stage = Path(tempfile.mkdtemp(prefix='pending-', dir=self.root))
            product = stage / 'product'
            product.mkdir()
            for name, data in files.items():
                out = product / name
                out.parent.mkdir(parents=True, exist_ok=True)
                with out.open('xb') as f:
                    f.write(data)
            (stage / 'manifest.json').write_bytes(raw)
            verify_tree(product, m)
            target.parent.mkdir(parents=True, exist_ok=True)
            stage.rename(target)
        if runtime not in m['compatibility']['renodeVersions']:
            raise ValueError('RenodeVersionMismatch')
        if old and old['current'] == identity:
            return {'status': 'Unchanged', **old}
        self.root.mkdir(parents=True, exist_ok=True)
        new = {'schema': 1, 'current': identity, 'previous': old['current'] if old else None}
        # Receipt is written first; a crash leaves an installed inactive version.
        # The active pointer is the only commit point; no destructive migrations.
        atomic_json(self.root / 'active.json', new)
        return {'status': 'Selected', **new}
