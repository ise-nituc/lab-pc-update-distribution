"""Normal-user bridge to a protected shared cache and the user's own WSL store."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


R = module('release_store')
CENTRAL = module('central_release')
ROOT = Path('C:/ProgramData/LabVirtualLabReleases')


def authority(test_only=False, launch=False):
    # Called by the simulator as well as the management entry. Never trust a
    # caller-provided path or a student-editable manifest as central approval.
    if os.name != 'nt':
        raise ValueError('WindowsRequired')
    shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', str(HERE / 'Check-ReleaseStore.ps1')],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return CENTRAL.approved(ROOT, test_only, verify_payload=not launch)


def dispatch(distro, mode, test_only=False, target=None):
    if not distro or any(ord(c) < 32 for c in distro):
        raise ValueError('InvalidDistro')
    identity, approved, folder = authority(test_only)
    request = {'mode': mode, 'identity': identity, 'approved': approved, 'bundle': str(folder),
               'testOnly': test_only, 'target': target, 'adapter': str(HERE)}
    token = base64.b64encode(json.dumps(request).encode()).decode()
    boot = ("import base64,json,subprocess,runpy,sys;"
            "r=json.loads(base64.b64decode(sys.argv[1]));"
            "p=subprocess.check_output(['wslpath','-u',r['adapter']],text=True).strip();"
            "sys.argv=[p+'/wsl_release.py',sys.argv[1]];runpy.run_path(sys.argv[0],run_name='__main__')")
    result = subprocess.run(['wsl.exe', '-d', distro, '--exec', '/usr/bin/python3', '-I', '-B', '-c', boot, token],
                            capture_output=True)
    try:
        record = json.loads(result.stdout.decode('utf-8'))
    except (UnicodeError, ValueError):
        raise ValueError('WSLReleaseReplyRejected') from None
    if result.returncode or record.get('status') == 'Stopped':
        print(json.dumps(record, sort_keys=True))
        raise ValueError('WSLReleaseOperationStopped')
    return record, folder


def new_project(destination, bundle, distro, test_only=False):
    """Opt-in sample creation only; never merge into an existing project/settings."""
    destination = R.plain(destination)
    if destination.exists():
        raise ValueError('ExistingProjectPreserved')
    raw = (bundle / 'manifest.json').read_bytes()
    m = R.manifest(raw, bundle.name, test_only)
    files = R.archive_files(bundle / 'payload.zip', m)
    contract = module('contract')
    template = json.loads((HERE / 'tasks.template.json').read_text(encoding='utf-8-sig'))
    replacements = {'${input:adapterRoot}': str(HERE), '${input:distro}': distro}
    for task in template['tasks']:
        task['args'] = [replacements.get(arg, arg.replace('${input:adapterRoot}', str(HERE))) for arg in task['args']]
        if test_only:
            task['args'].append('--test-only' if task['command'].endswith('python.exe') else '-TestOnly')
    template.pop('inputs', None)
    destination.mkdir(parents=True)
    (destination / 'src').mkdir()
    (destination / '.vscode').mkdir()
    (destination / 'platformio.ini').write_bytes(contract.INI)
    (destination / 'src/main.c').write_bytes(files['examples/adc-led-v1/main.c'])
    (destination / '.vscode/tasks.json').write_bytes(R.encoded(template))
    return destination


def fresh_user(distro, test_only=False):
    if distro != 'LabWSL-Docker-TestOnly-2404-v2':
        raise ValueError('FreshImportDistroMismatch')
    destination = R.plain(Path(os.environ['LOCALAPPDATA']) / 'LabPlatformIO-v2/projects/virtual-lab-first')
    if destination.exists():
        raise ValueError('ExistingProjectPreserved')
    authority(test_only)  # Approval/compatibility checked before the original initializer.
    shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    subprocess.run([str(shell), '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File',
                    'C:/ProgramData/LabUserSetup/20261106/New-UserWindows.ps1', '-Mode', 'Initialize'], check=True)
    record, bundle = dispatch(distro, 'prepare', test_only)
    new_project(destination, bundle, distro, test_only)
    return record


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['check', 'prepare', 'update', 'rollback', 'runtimecheck', 'host-check', 'fresh'])
    p.add_argument('--distro', required=True)
    p.add_argument('--to')
    p.add_argument('--new-project', type=Path)
    p.add_argument('--test-only', action='store_true')
    args = p.parse_args()
    if os.name != 'nt':
        raise ValueError('WindowsRequired')
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('ElevationRejected')
    if args.mode == 'host-check':
        identity, _, _ = authority(args.test_only)
        print(json.dumps({'status': 'HostReleaseReady', 'available': identity}))
        return
    if args.mode == 'fresh':
        if args.new_project is not None or args.to is not None:
            raise ValueError('FreshArgumentsRejected')
        print(json.dumps(fresh_user(args.distro, args.test_only), sort_keys=True))
        return
    if args.to is not None and args.mode != 'rollback':
        raise ValueError('RollbackTargetOnly')
    if args.to is not None:
        R.hash_id(args.to)
    if args.new_project is not None:
        if args.mode != 'prepare':
            raise ValueError('ProjectCreationOnlyDuringPrepare')
        if R.plain(args.new_project).exists():
            raise ValueError('ExistingProjectPreserved')
    record, bundle = dispatch(args.distro, args.mode, args.test_only, args.to)
    if args.new_project is not None:
        new_project(args.new_project, bundle, args.distro, args.test_only)
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        known = {'ElevationRejected', 'ExistingProjectPreserved', 'WSLReleaseReplyRejected',
                 'WSLReleaseOperationStopped', 'WindowsRequired', 'FreshImportDistroMismatch',
                 'RollbackTargetOnly', 'ProjectCreationOnlyDuringPrepare'}
        reason = str(error) if isinstance(error, ValueError) and str(error) in known else 'VirtualLabUpdateRejected'
        print(json.dumps({'status': 'Stopped', 'reason': reason}))
        raise SystemExit(1)
