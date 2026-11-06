"""Current user's WSL supervisor; owns only the processes it creates."""
import base64
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sim_contract', HERE / 'contract.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
spec = importlib.util.spec_from_file_location('release_store', HERE / 'release_store.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
spec = importlib.util.spec_from_file_location('wsl_release', HERE / 'wsl_release.py')
RELEASES = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RELEASES)


class Lease:
    def __init__(self, stream):
        self.last = time.monotonic()
        self.closed = False
        def read():
            try:
                for line in stream:
                    if line != 'ALIVE\n':
                        break
                    self.last = time.monotonic()
            finally:
                self.closed = True
        threading.Thread(target=read, daemon=True).start()

    def check(self):
        if self.closed or time.monotonic() - self.last > 6:
            raise RuntimeError('WindowsTaskEnded')


def stop_owned(proc):
    if proc is None:
        return
    # Each child starts a new group. Never find/kill by name, port, or saved PID.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=3)


def ports_free(ports=(4567, 8001)):
    for port in ports:
        with socket.socket() as sock:
            # Match ThreadingHTTPServer: TIME_WAIT is not a live listener.
            # SO_REUSEADDR still refuses an actual listening socket.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('127.0.0.1', port))
            except OSError as error:
                raise OSError('PortInUse:' + str(port)) from error


def verify_product(root):
    pins = json.loads((HERE / 'virtual-lab-lock.json').read_text(encoding='utf-8-sig'))
    for name, expected in pins.items():
        if C.digest(C.plain(root / name).read_bytes()) != expected:
            raise ValueError('VirtualLabSnapshotMismatch')


def state():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:8001/api/state', timeout=1) as response:
        result = json.load(response)
    if result.get('connected') is not True:
        raise ValueError('BridgeNotConnected')


def wait_ready(check, children, lease, timeout):
    deadline = time.monotonic() + timeout
    while True:
        lease.check()
        if any(p.poll() is not None for p in children):
            raise RuntimeError('OwnedProcessExited')
        if check():
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('StartupTimeout')
        time.sleep(0.1)


def run(request, lease):
    if os.geteuid() == 0 or request.get('profile') != 'adc-led-v1':
        raise ValueError('UserOrProfileRejected')
    # Persistent lock inode: never unlink it, including after failures.
    lockdir = Path.home() / '.local/state/lab-simulator'
    C.plain(lockdir)
    lockdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lockpath = C.plain(lockdir / 'session.lock')
    with lockpath.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('SimulatorAlreadyRunning') from None
        ports_free()
        store = R.Store(R.user_root(), request['approved'], request.get('testOnly', False))
        root, release, selected = store.selected(verify_files=False)
        print('Virtual Lab manifest: ' + selected['current'] + ' commit: ' + release['commit'], flush=True)
        elf = Path(subprocess.check_output(['wslpath', '-u', request['elf']], text=True).strip())
        data = C.plain(elf).read_bytes()
        if C.digest(data) != request['sha256']:
            raise ValueError('ArtifactMismatch')
        entry, sp = C.boot_values(data)
        # ASCII-only Monitor paths: user path (Japanese/spaces) never becomes Monitor code.
        # New /tmp directory is 0700. Keep diagnostics, do not touch shared snapshot.
        session = Path(tempfile.mkdtemp(prefix='lab-simulator-', dir='/tmp'))
        (session / 'firmware.elf').write_bytes(data)
        (session / 'product').symlink_to(root, target_is_directory=True)
        print('Session logs: ' + str(session) + ' (private; do not commit)', flush=True)
        supervise(session, entry, sp, lease)


def supervise(session, entry, sp, lease):
    master, slave = pty.openpty()
    renode = gui = None
    log = (session / 'renode.log').open('xb', buffering=0)
    gui_log = (session / 'gui.log').open('xb', buffering=0)
    pumping = threading.Event()
    def pump():
        while not pumping.is_set():
            try:
                if select.select([master], [], [], 0.1)[0]:
                    block = os.read(master, 8192)
                    if not block:
                        break
                    log.write(block)
            except OSError:
                break
    try:
        env = dict(os.environ, VLAB_BRIDGE_PORT='4567', VLAB_HTTP_PORT='8001',
                   PYTHONDONTWRITEBYTECODE='1',
                   XDG_CONFIG_HOME=str(session / 'config'), XDG_CACHE_HOME=str(session / 'cache'),
                   XDG_STATE_HOME=str(session / 'state'), DOTNET_CLI_HOME=str(session / 'dotnet'))
        renode = subprocess.Popen(['/usr/local/bin/lab-renode', '--console', '--disable-gui'], cwd=session,
                                  stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        os.close(slave)
        slave = None
        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        contains = lambda marker: marker in (session / 'renode.log').read_bytes()
        wait_ready(lambda: contains(b'Renode'), [renode], lease, 45)
        product = session / 'product'
        commands = [f'include @{product}/renode/scripts/platform.resc',
                    f'sysbus LoadELF @{session}/firmware.elf',
                    f'cpu VectorTableOffset 0x08000000', f'cpu PC 0x{entry:X}', f'cpu SP 0x{sp:X}',
                    f'i @{product}/bridge/renode_bridge.py', 'start']
        os.write(master, ('\n'.join(commands) + '\n').encode('ascii'))
        wait_ready(lambda: contains(b'bridge listening on 127.0.0.1:4567'), [renode], lease, 45)
        gui = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(product / 'gui/app.py')], cwd=session,
                               stdout=gui_log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        def ready():
            # Bind marker must come from our own GUI, then check bridge API.
            if b'Virtual Lab: http://127.0.0.1:8001' not in (session / 'gui.log').read_bytes():
                return False
            monitor = (session / 'renode.log').read_text(errors='replace')
            if any(word in monitor.lower() for word in ('error', 'exception', 'could not', 'no such')):
                raise RuntimeError('MonitorCommandFailed')
            if 'Machine started' not in monitor:
                return False
            try:
                state()
                return True
            except (OSError, ValueError):
                return False
        wait_ready(ready, [renode, gui], lease, 20)
        print('SIMULATOR READY: http://127.0.0.1:8001 — Ctrl+C / Task stop ends this session.', flush=True)
        while True:
            lease.check()
            if renode.poll() is not None or gui.poll() is not None:
                raise RuntimeError('OwnedProcessExited')
            time.sleep(0.2)
    finally:
        stop_owned(gui)
        stop_owned(renode)
        pumping.set()
        if 'thread' in locals():
            thread.join(2)
        os.close(master)
        if slave is not None:
            os.close(slave)
        log.close()
        gui_log.close()


def main():
    request = json.loads(base64.b64decode(sys.argv[1], validate=True))
    lease = Lease(sys.stdin)
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        run(request, lease)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        reason = str(error) if isinstance(error, (ValueError, RuntimeError)) or str(error).startswith('PortInUse:') else type(error).__name__
        print('SIMULATOR STOPPED: ' + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
