"""Download a teacher-approved manifest to the protected host store (admin wrapper only)."""
import argparse
import importlib.util
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('releases', Path(__file__).with_name('release_store.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


def select_cached(root, identity, test_only=False):
    """Admin explicitly selects an already approved host copy; works offline."""
    root = R.plain(root)
    R.hash_id(identity)
    with R.file_lock(root / 'store.lock'):
        folder = R.plain(root / 'releases' / identity)
        m = R.manifest(R.plain(folder / 'manifest.json').read_bytes(), identity, test_only)
        R.archive_files(folder / 'payload.zip', m)
        desired = {'schema': 1, 'manifest': identity}
        R.atomic_json(root / 'available.json', desired)
        return desired


def sync(root, url, identity, test_only=False, fetch=R.download, verify_host=None):
    root = R.plain(root)
    with R.file_lock(root / 'store.lock'):
        raw = fetch(R.https_url(url), 1024 * 1024)
        m = R.manifest(raw, identity, test_only)
        folder = R.plain(root / 'releases' / identity)
        if folder.exists():
            if (folder / 'manifest.json').read_bytes() != raw:
                raise ValueError('ExistingCentralManifestMismatch')
            R.archive_files(folder / 'payload.zip', m)
        else:
            archive = fetch(m['archive']['url'], R.MAX_ARCHIVE)
            stage = Path(tempfile.mkdtemp(prefix='pending-', dir=root))
            (stage / 'manifest.json').write_bytes(raw)
            (stage / 'payload.zip').write_bytes(archive)
            R.archive_files(stage / 'payload.zip', m)
            folder.parent.mkdir(parents=True, exist_ok=True)
            stage.rename(folder)
        if verify_host is not None:
            verify_host()  # Check newly created owners/ACLs before making them available.
        old = R.parse((root / 'available.json').read_bytes()) if (root / 'available.json').exists() else None
        desired = {'schema': 1, 'manifest': identity}
        if old != desired:
            R.atomic_json(root / 'available.json', desired)
        return desired


def approved(root, test_only=False, verify_payload=True):
    root = R.plain(root)
    pointer = R.parse(R.plain(root / 'available.json').read_bytes())
    if set(pointer) != {'schema', 'manifest'} or pointer['schema'] != 1:
        raise ValueError('CentralStateRejected')
    R.hash_id(pointer['manifest'])
    known = []
    for folder in R.plain(root / 'releases').iterdir():
        R.plain(folder)
        R.hash_id(folder.name)
        # TestOnly opt-in applies to selection, not enumeration of old approvals.
        R.manifest(R.plain(folder / 'manifest.json').read_bytes(), folder.name, True)
        known.append(folder.name)
    if pointer['manifest'] not in known:
        raise ValueError('CentralTargetMissing')
    folder = root / 'releases' / pointer['manifest']
    m = R.manifest((folder / 'manifest.json').read_bytes(), pointer['manifest'], test_only)
    if verify_payload:
        R.archive_files(folder / 'payload.zip', m)
    return pointer['manifest'], sorted(known), folder


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', required=True, type=Path)
    p.add_argument('--url')
    p.add_argument('--select-cached', action='store_true')
    p.add_argument('--sha256', required=True)
    p.add_argument('--test-only', action='store_true')
    args = p.parse_args()
    # Public CLI must never write an arbitrary elevated target.
    import os
    if os.name != 'nt':
        raise ValueError('WindowsAdminWrapperRequired')
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('WindowsAdminWrapperRequired')
    if args.root != Path('C:/ProgramData/LabVirtualLabReleases'):
        raise ValueError('UnexpectedCentralStore')
    if args.select_cached:
        if args.url is not None:
            raise ValueError('CachedSelectionNeedsNoURL')
        print(select_cached(args.root, args.sha256, args.test_only))
    else:
        if args.url is None:
            raise ValueError('ManifestURLRequired')
        import subprocess
        shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        def protected():
            subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File',
                            str(Path(__file__).with_name('Check-ReleaseStore.ps1'))], check=True)
        print(sync(args.root, args.url, args.sha256, args.test_only, verify_host=protected))


if __name__ == '__main__':
    main()
