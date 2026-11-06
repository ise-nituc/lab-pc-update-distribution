"""User-scoped release preparation/update/rollback, dispatched from Windows."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

spec = importlib.util.spec_from_file_location('releases', Path(__file__).with_name('release_store.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
spec = importlib.util.spec_from_file_location('runtime_identity', Path(__file__).with_name('runtime_identity.py'))
IDENTITY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IDENTITY)


def runtime_info():
    result = subprocess.run(['/usr/local/bin/lab-renode', '--version'],
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ValueError('UnsupportedRenodeRuntime')
    return IDENTITY.parse_banner(result.stdout + '\n' + result.stderr)


def runtime_version():
    return runtime_info()['compatibilityVersion']


def windows_path(value):
    return Path(subprocess.check_output(['wslpath', '-u', value], text=True).strip())


def execute(request):
    if os.geteuid() == 0:
        raise ValueError('NonRootWSLUserRequired')
    store = R.Store(R.user_root(), request['approved'], request.get('testOnly', False))
    mode = request['mode']
    if mode == 'runtimecheck':
        return {'status': 'RuntimeAccepted', **runtime_info()}
    if mode == 'check':
        old = store.state()
        if old:
            store.selected()
        return {'status': 'Prepared' if old else 'PreparationRequired', 'current': old['current'] if old else None,
                'previous': old['previous'] if old else None,
                'available': request['identity'], 'updateAvailable': bool(old and old['current'] != request['identity'])}
    # Same inode as simulator session; reject before staging or state mutation.
    with R.file_lock(R.session_lock()):
        identity = request['identity'] if mode != 'rollback' else request.get('target')
        raw = archive = None
        if mode in ('prepare', 'update'):
            bundle = windows_path(request['bundle'])
            raw = R.plain(bundle / 'manifest.json').read_bytes()
            archive = R.plain(bundle / 'payload.zip')
        return store.apply(mode, identity, raw, archive, runtime_version())


if __name__ == '__main__':
    try:
        request = json.loads(base64.b64decode(sys.argv[1], validate=True))
        print(json.dumps(execute(request), sort_keys=True), flush=True)
    except Exception as error:
        # Fixed code only: never include subprocess output, user paths or names.
        if isinstance(error, BlockingIOError):
            code = 'SimulatorOrUpdateInUse'
        else:
            code = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Za-z]+', str(error)) else 'ReleaseOperationRejected'
        print(json.dumps({'status': 'Stopped', 'reason': code}), flush=True)
        sys.exit(1)
