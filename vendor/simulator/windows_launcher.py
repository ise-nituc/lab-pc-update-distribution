"""Build a fresh snapshot with the installed PlatformIO Core, then run WSL."""
import argparse
import base64
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sim_contract', HERE / 'contract.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
PYTHON = Path('C:/ProgramData/LabPlatformIO-v2/releases/pio-ststm32-20261102-v2/runtime/penv/Scripts/python.exe')


def inventory(project):
    C.plain(project)
    ini = C.plain(project / 'platformio.ini').read_bytes()
    if ini.replace(b'\r\n', b'\n') != C.INI:
        raise ValueError('UnapprovedProjectConfiguration')
    result = {'platformio.ini': ini}
    for name in ('src', 'include', 'lib'):
        directory = C.plain(project / name)
        if directory.exists():
            for path in directory.rglob('*'):
                C.plain(path)
                if path.is_file():
                    result[path.relative_to(project).as_posix()] = path.read_bytes()
    if 'src/main.c' not in result:
        raise ValueError('SourceMissing')
    return result


def fresh_build(project, projects, invoke):
    before = inventory(project)
    stage = C.plain(projects) / ('simulator-' + uuid.uuid4().hex)
    stage.mkdir()
    for name, data in before.items():
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    # This path did not exist before this invocation. Never read project/.pio.
    invoke(stage)
    if inventory(project) != before or inventory(stage) != before:
        raise ValueError('SourceChangedDuringBuild')
    elf = C.plain(stage / '.pio/build' / C.ENV / 'firmware.elf')
    data = elf.read_bytes()
    frozen = stage / 'simulator.elf'
    with frozen.open('xb') as stream:
        stream.write(data)
    return frozen, C.digest(data)


def build(stage):
    # Same installed Core and per-user Junctions as the standard VS Code Build.
    # Only this child process receives these variables; settings are untouched.
    env = os.environ.copy()
    env['PLATFORMIO_CORE_DIR'] = str(Path(env['LOCALAPPDATA']) / 'LabPlatformIO-v2/core')
    env['PLATFORMIO_BUILD_DIR'] = str(stage / '.pio/build')
    env['PLATFORMIO_DISABLE_UPGRADE_CHECK'] = 'true'
    print('BUILD: PlatformIO run / ' + C.ENV, flush=True)
    with (stage / 'simulator-build.log').open('xb') as log:
        proc = subprocess.Popen([str(PYTHON), '-I', '-B', '-m', 'platformio', 'run',
                                 '--project-dir', str(stage), '--environment', C.ENV],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for raw in iter(proc.stdout.readline, b''):
                log.write(raw)
                print(raw.decode('utf-8', errors='replace').rstrip(), flush=True)
            if proc.wait():
                raise ValueError('BuildFailed')
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()
            proc.stdout.close()


def find_chrome():
    return next((p for p in (
        Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Google/Chrome/Application/chrome.exe',
        Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Google/Chrome/Application/chrome.exe',
        Path(os.environ['LOCALAPPDATA']) / 'Google/Chrome/Application/chrome.exe') if p.is_file()), None)


def enable_ctrl_c():
    # Windows process groups can inherit the parent's ignore-CTRL_C flag.
    # Restore handling for this launcher only; do not signal other processes.
    if os.name == 'nt':
        import ctypes
        signal.signal(signal.SIGINT, signal.default_int_handler)
        if not ctypes.windll.kernel32.SetConsoleCtrlHandler(None, False):
            raise ctypes.WinError()


def wait_interruptible(proc):
    # A Windows infinite native-process wait can delay Python Ctrl+C handling.
    while proc.poll() is None:
        time.sleep(0.2)
    return proc.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--distro', required=True)
    parser.add_argument('--profile', choices=['adc-led-v1'], default='adc-led-v1')
    parser.add_argument('--test-only', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt':
        raise ValueError('WindowsRequired')
    enable_ctrl_c()
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('ElevationRejected')
    if not args.distro or any(ord(c) < 32 for c in args.distro):
        raise ValueError('InvalidDistro')
    release_spec = importlib.util.spec_from_file_location('windows_release', HERE / 'windows_release.py')
    releases = importlib.util.module_from_spec(release_spec)
    release_spec.loader.exec_module(releases)
    _, approved, _ = releases.authority(args.test_only, launch=True)
    # Preparation/update validates the installed source; WSL runner selects it.
    chrome = find_chrome()
    project = args.project.absolute()
    projects = Path(os.environ['LOCALAPPDATA']) / 'LabPlatformIO-v2/projects'
    elf, sha = fresh_build(project, projects, build)
    print('Fresh ELF SHA256: ' + sha, flush=True)
    # Base64 is one shell-inert argument even with legacy wsl.exe quoting.
    request = dict(elf=str(elf), sha256=sha, adapter=str(HERE), profile=args.profile,
                   approved=approved, testOnly=args.test_only)
    encoded = base64.b64encode(json.dumps(request).encode()).decode()
    boot = ("import base64,json,subprocess,runpy,sys;"
            "r=json.loads(base64.b64decode(sys.argv[1]));"
            "p=subprocess.check_output(['wslpath','-u',r['adapter']],text=True).strip();"
            "sys.argv=[p+'/wsl_runner.py',sys.argv[1]];runpy.run_path(sys.argv[0],run_name='__main__')")
    proc = subprocess.Popen(['wsl.exe', '-d', args.distro, '--exec', '/usr/bin/python3', '-I', '-B', '-c', boot, encoded],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    ended = threading.Event()
    def heartbeat():
        while not ended.is_set():
            try:
                proc.stdin.write(b'ALIVE\n')
                proc.stdin.flush()
            except (OSError, ValueError):
                return
            ended.wait(1)
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    failures = []
    def output():
        try:
            for raw in iter(proc.stdout.readline, b''):
                line = raw.decode('utf-8', errors='replace').strip()
                print(line, flush=True)
                if line.startswith('SIMULATOR READY:'):
                    # WSL readiness alone does not prove Windows localhost forwarding.
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open('http://127.0.0.1:8001/api/state', timeout=5) as response:
                        if json.load(response).get('connected') is not True:
                            raise ValueError('WindowsGUIUnavailable')
                    print('Web GUI: http://127.0.0.1:8001', flush=True)
                    if chrome is not None:
                        subprocess.Popen([str(chrome), 'http://127.0.0.1:8001'])
                    else:
                        print('Chrome was not found automatically. Open the URL in Chrome.', flush=True)
        except Exception:
            failures.append('WindowsGUIUnavailable')
            ended.set()
            proc.stdin.close()
    output_thread = threading.Thread(target=output, daemon=True)
    output_thread.start()
    try:
        print('Build verified. Waiting for Renode / bridge / Web GUI.', flush=True)
        code = wait_interruptible(proc)
        return 1 if failures else code
    except KeyboardInterrupt:
        return 130
    finally:
        ended.set()
        thread.join(2)
        proc.stdin.close()  # EOF/heartbeat expiry also works after forced Task termination.
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            proc.terminate()
        output_thread.join(2)
        proc.stdout.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('SIMULATOR STOPPED: ' + reason + '. No old ELF was used.', file=sys.stderr)
        sys.exit(1)
