"""Approved APT transition adapter; delegates installation/check to existing labenv."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


class Rejected(ValueError):
    pass


def load_labenv():
    path = Path(__file__).resolve().parents[2] / 'vendor/wsl/labenv.py'
    spec = importlib.util.spec_from_file_location('approved_labenv', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def validate_config(config):
    if set(config) != {'target', 'packages', 'sources', 'approvedChanges', 'probes'}:
        raise Rejected('AptConfigRejected')
    if config['target'] != {'id': 'ubuntu', 'version': '24.04'}:
        raise Rejected('Ubuntu2404Required')
    if not 1 <= len(config['packages']) <= 20 or not config['sources']:
        raise Rejected('PackageSetRejected')
    seen = set()
    for pkg in config['packages']:
        if set(pkg) != {'name', 'version'} or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', pkg['name']) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', pkg['version']) or pkg['name'] in seen:
            raise Rejected('PackageRecordRejected')
        seen.add(pkg['name'])
    for source in config['sources']:
        if set(source) != {'uri', 'suite', 'component', 'architecture'} or not source['uri'].startswith(('http://', 'https://')) or '@' in source['uri']:
            raise Rejected('SourceRecordRejected')
    change_names = set()
    for row in config['approvedChanges']:
        if set(row) != {'name', 'from', 'to'} or row['name'] in change_names:
            raise Rejected('ChangeRecordRejected')
        change_names.add(row['name'])
    # No arbitrary verification commands from a YAML file.
    if any(p not in ('make-version', 'git-version', 'python-version', 'gcc-version') for p in config['probes']):
        raise Rejected('UnknownProbe')


def source_matches(system, name, version, allowed):
    text = system.run(['apt-cache', 'policy', name])
    selected = False
    found = []
    for line in text.splitlines():
        header = re.match(r'^\s*(?:\*\*\*\s*)?(\S+)\s+[0-9]+\s*$', line)
        if header:
            selected = header[1] == version
            continue
        if selected:
            row = re.match(r'^\s*[0-9]+\s+(https?://\S+)\s+(\S+)/(\S+)\s+(\S+)\s+Packages\s*$', line)
            if row:
                found.append({'uri': row[1].rstrip('/'), 'suite': row[2], 'component': row[3], 'architecture': row[4]})
    normalized = [{**a, 'uri': a['uri'].rstrip('/')} for a in allowed]
    if not found or any(row not in normalized for row in found):
        raise Rejected('PackageSourceNotApproved')


def describe(labenv, system, config):
    validate_config(config)
    doc = {'schema_version': 1, 'name': 'approved-small-set', 'target': config['target'], 'packages': config['packages']}
    labenv.environment(system, doc)
    if system.run(['dpkg', '--audit']).strip():
        raise Rejected('DpkgNeedsAdminRepair')
    rows = labenv.check(system, doc)
    probe_commands = {'make-version': ('make', ['/usr/bin/make', '--version']),
                      'git-version': ('git', ['/usr/bin/git', '--version']),
                      'python-version': ('python3', ['/usr/bin/python3', '--version']),
                      'gcc-version': ('gcc', ['/usr/bin/gcc', '--version'])}
    before_checks = []
    for probe in config['probes']:
        package, command = probe_commands[probe]
        if system.installed(package) is not None:
            system.run(command)
            before_checks.append(probe)
    # Even a no-op must retain the approved version's repository constraint.
    for package in config['packages']:
        source_matches(system, package['name'], package['version'], config['sources'])
    if all(r['match'] for r in rows):
        return {'needed': False, 'changes': [], 'requested': config['packages'], 'checksBefore': before_checks}, doc
    _, resolved, simulation = labenv.plan(system, doc)
    if re.search(r'^Remv\s', simulation, re.M):
        raise Rejected('RemovalRejected')
    changes = []
    for line in simulation.splitlines():
        if not line.startswith('Inst '):
            continue
        match = re.match(r'^Inst ([a-z0-9][a-z0-9+.:-]*)(?: \[[^\]]+\])? \(([^\s)]+)', line)
        if not match:
            raise Rejected('SimulationRejected')
        name, version = match[1], match[2]
        before = system.installed(name)
        row = {'name': name, 'from': before, 'to': version}
        if row not in config['approvedChanges']:
            raise Rejected('DependencyChangeNotApproved')
        source_matches(system, name, version, config['sources'])
        # apt's default downgrade refusal is retained; explicit preflight as well.
        if before is not None:
            compare = getattr(system, 'is_downgrade', None)
            if compare is None:
                bad = subprocess.run(['dpkg', '--compare-versions', before, 'gt', version]).returncode == 0
            else:
                bad = compare(before, version)
            if bad:
                raise Rejected('DowngradeRejected')
        changes.append(row)
    if not changes and not all(r['match'] for r in rows):
        raise Rejected('ExpectedChangesMissing')
    return {'needed': True, 'changes': sorted(changes, key=lambda r: r['name']), 'requested': resolved, 'checksBefore': before_checks}, doc


def operate(labenv, system, config, phase, approved_plan=None, root=False):
    plan, doc = describe(labenv, system, config)
    reply = {'status': 'Unchanged', 'changed': [], 'retry': 'manual', 'errorCode': ''}
    if phase == 'check':
        reply['status'] = 'NeedsUpdate' if plan['needed'] else 'Unchanged'
    elif phase == 'plan':
        reply.update(status='Planned', plan=plan)
    elif phase == 'apply':
        if not plan['needed']:
            return reply
        if not root:
            raise Rejected('LinuxRootRequired')
        if approved_plan != plan:
            raise Rejected('DependencyPlanChanged')
        # Reuse original update implementation, but guard its second simulation
        # and installation boundary against repository/state changes.
        delegate = system
        expected = plan
        class Guarded:
            def __getattr__(self, name):
                return getattr(delegate, name)
            def install(self, args, emit):
                now, _ = describe(labenv, delegate, config)
                if now != expected:
                    raise Rejected('DependencyPlanChanged')
                options = ['-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::AllowInsecureRepositories=false']
                return delegate.install([args[0]] + options + args[1:], emit)
        events = []
        labenv.update(Guarded(), doc, False, lambda: True, events.append)
        reply.update(status='Applied', changed=plan['changes'])
    elif phase == 'verify':
        if plan['needed']:
            raise Rejected('PostInstallVersionMismatch')
        probes = {'make-version': ['/usr/bin/make', '--version'], 'git-version': ['/usr/bin/git', '--version'],
                  'python-version': ['/usr/bin/python3', '--version'], 'gcc-version': ['/usr/bin/gcc', '--version']}
        for probe in config['probes']:
            system.run(probes[probe])
        reply['status'] = 'Verified'
    else:
        raise Rejected('NotSupported')
    return reply


def main():
    phase, token = sys.argv[1:]
    context = json.loads(base64.b64decode(token))
    system = None
    before = {}
    try:
        labenv = load_labenv()
        system = labenv.System()
        names = {p['name'] for p in context['config']['packages']} | {p['name'] for p in context['config']['approvedChanges']}
        before = {name: system.installed(name) for name in names}
        reply = operate(labenv, system, context['config'], phase, context.get('plan'), os.geteuid() == 0)
        print(json.dumps(reply, sort_keys=True))
    except Exception as error:
        reason = str(error) if isinstance(error, Rejected) else 'AptOperationFailed'
        changed, extent = [], 'None'
        if phase == 'apply':
            extent = 'UnknownPartial'
            if system is not None and before:
                try:
                    for name, old in before.items():
                        now = system.installed(name)
                        if now != old:
                            changed.append({'name': name, 'from': old, 'to': now})
                    extent = 'ObservedPackageVersions'
                except Exception:
                    pass
        print(json.dumps({'status': 'NeedsAdminRepair' if phase == 'apply' else 'Failed', 'changed': changed,
                          'retry': 'manual', 'errorCode': reason, 'changeExtent': extent}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
