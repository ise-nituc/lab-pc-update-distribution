"""Small, local APT manifest prototype. No shell, privilege escalation or reset."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    raise SystemExit('PyYAML is required: bootstrap with Ubuntu python3-yaml; see scripts/wsl/README.md')


class LabError(Exception):
    pass


def safe_output(text):
    """Suppress terminal commands and redact URL credentials before either sink."""
    text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', text)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', text)
    text = re.sub(r'(?i)\b[a-z][a-z0-9+.-]*://[^\s<>]+', '[repository URL omitted]', text)
    text = re.sub(r'(?i)\b(authorization|password|token|secret)\s*[:=]\s*\S+', r'\1=[redacted]', text)
    return text


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise LabError('YAML keys must be unique strings (merge keys unsupported)')
        result[key] = loader.construct_object(value_node)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise LabError('Missing or unknown manifest keys')


def load_manifest(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise LabError('Manifest exceeds 64 KiB')
    try:
        doc = yaml.load(raw.decode('utf-8'), Loader=StrictLoader)
    except (yaml.YAMLError, UnicodeError) as exc:
        raise LabError('Invalid YAML') from exc
    keys(doc, ('schema_version', 'name', 'target', 'packages'))
    if type(doc['schema_version']) is not int or doc['schema_version'] != 1:
        raise LabError('Unsupported schema version')
    name = doc['name']
    if not isinstance(name, str) or len(name) > 64 or not re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', name):
        raise LabError('Invalid manifest name: use a lowercase identifier (maximum 64 characters)')
    keys(doc['target'], ('id', 'version'))
    if doc['target'] != {'id': 'ubuntu', 'version': '24.04'}:
        raise LabError('Only Ubuntu 24.04 is supported')
    if not isinstance(doc['packages'], list) or not 1 <= len(doc['packages']) <= 100:
        raise LabError('packages must be a nonempty list (maximum 100)')
    seen = set()
    for package in doc['packages']:
        keys(package, ('name',), ('version',))
        name = package['name']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', name) or name in seen:
            raise LabError('Invalid or duplicate package name')
        seen.add(name)
        if 'version' in package and (not isinstance(package['version'], str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', package['version'])):
            raise LabError('version must be a quoted, exact Debian version')
    return doc, hashlib.sha256(raw).hexdigest()


class System:
    def install(self, args, emit):
        # One pipe preserves the order observed from both streams. No PTY or
        # interactive progress UI; newline output works for terminals and JSONL.
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding='utf-8', errors='replace',
                              env={**os.environ, 'LC_ALL': 'C.UTF-8'}) as process:
            try:
                for line in process.stdout:
                    emit({'event': 'apt-output', 'text': safe_output(line.rstrip('\n'))})
                code = process.wait()
            except BaseException:
                process.terminate()
                process.wait()
                raise
        emit({'event': 'apt-exit', 'exit_code': code})
        if code:
            raise LabError('apt-get failed (exit {}); see preceding apt-output events'.format(code))

    def run(self, args):
        result = subprocess.run(args, capture_output=True, text=True, env={**os.environ, 'LC_ALL': 'C'})
        if result.returncode:
            raise LabError('{} failed (exit {})'.format(args[0], result.returncode))
        return result.stdout

    def environment(self):
        values = {}
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                values[key] = value.strip('"')
        return {'id': values.get('ID'), 'version': values.get('VERSION_ID')}

    def installed(self, name):
        # Query the complete installed database: absence is distinct from query failure.
        output = self.run(['dpkg-query', '-W', '-f=${Package}\t${Status}\t${Version}\n'])
        for line in output.splitlines():
            fields = line.split('\t')
            if len(fields) == 3 and fields[0] == name and fields[1] == 'install ok installed':
                return fields[2]
        return None


def environment(system, doc):
    observed = system.environment()
    if observed != doc['target']:
        raise LabError('Environment mismatch: requires Ubuntu 24.04')
    return observed


def check(system, doc):
    rows = []
    for package in doc['packages']:
        installed = system.installed(package['name'])
        requested = package.get('version')
        rows.append({'name': package['name'], 'requested': requested or 'ubuntu-candidate',
                     'installed': installed, 'match': installed is not None and (requested is None or installed == requested)})
    return rows


def plan(system, doc):
    specs = []
    resolved = []
    for package in doc['packages']:
        name = package['name']
        policy = system.run(['apt-cache', 'policy', name])
        candidate = re.search(r'^\s*Candidate:\s+(\S+)', policy, re.MULTILINE)
        wanted = package.get('version')
        if wanted is None:
            if not candidate or candidate[1] == '(none)':
                raise LabError('No APT candidate: ' + name)
            wanted = candidate[1]
        available = system.run(['apt-cache', 'madison', name])
        versions = [line.split('|')[1].strip() for line in available.splitlines() if len(line.split('|')) >= 3]
        if wanted not in versions:
            raise LabError('Requested version unavailable: ' + name + '=' + wanted)
        specs.append(name + '=' + wanted)
        resolved.append({'name': name, 'version': wanted})
    # Approve once; retain APT safety refusals and use plain, line-based output.
    args = ['apt-get', '-o', 'Dpkg::Use-Pty=0', '-o', 'APT::Color=0',
            '-o', 'Dpkg::Progress-Fancy=0', '--assume-yes', '--no-remove', 'install', '--'] + specs
    simulation = system.run(['apt-get', '--simulate', '--no-remove', 'install', '--'] + specs)
    if re.search(r'^Remv\s|\b[1-9][0-9]* to remove\b', simulation, re.MULTILINE):
        raise LabError('APT proposes package removal; stopped')
    return args, resolved, simulation


def update(system, doc, dry_run, approve, emit):
    args, resolved, simulation = plan(system, doc)
    emit({'event': 'plan', 'command': args, 'resolved': resolved, 'simulation': simulation})
    if dry_run:
        return 0
    if not approve():
        raise LabError('Explicit approval not received')
    if os.geteuid() != 0:
        raise LabError('Apply requires root; run sudo explicitly after reviewing the plan')
    # --no-remove remains active even if repository or package state changes after simulation.
    system.install(args, emit)
    emit({'event': 'apt-complete'})
    rows = check(system, doc)
    for row, expected in zip(rows, resolved):
        row['resolved'] = expected['version']
        row['match'] = row['installed'] == expected['version']
    emit({'event': 'installed', 'packages': rows})
    if not all(row['match'] for row in rows):
        raise LabError('Post-install version verification failed')
    return 0


def main(mode):
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    if mode == 'update':
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--log-dir', type=Path, default=Path.home() / '.local/state/labenv')
    else:
        parser.add_argument('--json', action='store_true', help='JSON to stdout')
    options = parser.parse_args()
    log = None
    def emit(value):
        # Sanitize nested APT simulation/error strings as well as live output.
        def clean(item):
            if isinstance(item, str):
                return safe_output(item)
            if isinstance(item, dict):
                return {key: clean(val) for key, val in item.items()}
            if isinstance(item, list):
                return [clean(val) for val in item]
            return item
        text = json.dumps(clean(value), ensure_ascii=False)
        if log:
            log.write(text + '\n')
            log.flush()
        print(text, flush=True)
    try:
        if mode == 'update':
            options.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            filename = datetime.now(timezone.utc).strftime('update-%Y%m%dT%H%M%S.%fZ.jsonl')
            log = (options.log_dir / filename).open('x', encoding='utf-8')
            emit({'event': 'start', 'time': datetime.now(timezone.utc).isoformat(), 'dry_run': options.dry_run})
        doc, digest = load_manifest(options.manifest)
        system = System()
        observed = environment(system, doc)
        if mode == 'update':
            emit({'event': 'manifest', 'sha256': digest, 'environment': observed})
            code = update(system, doc, options.dry_run,
                          lambda: input('Apply this APT plan? Type APPLY: ') == 'APPLY', emit)
            emit({'event': 'finish', 'exit_code': code})
            return code
        rows = check(system, doc)
        result = {'schema_version': 1, 'time': datetime.now(timezone.utc).isoformat(),
                  'environment': observed, 'manifest_sha256': digest, 'packages': rows}
        if options.json:
            emit(result)
        else:
            print('Ubuntu ' + observed['version'])
            for row in rows:
                print('{}: installed={} requested={} {}'.format(row['name'], row['installed'] or 'missing', row['requested'], 'MATCH' if row['match'] else 'MISMATCH'))
        return 0 if all(row['match'] for row in rows) else 1
    except (LabError, OSError, EOFError, KeyboardInterrupt) as exc:
        if mode == 'check' and options.json:
            emit({'error': str(exc), 'exit_code': 2})
        else:
            emit({'event': 'error', 'message': str(exc), 'exit_code': 2})
        return 2
    finally:
        if log:
            log.close()
