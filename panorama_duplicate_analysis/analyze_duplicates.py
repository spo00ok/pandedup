#!/usr/bin/env python3
"""Panorama XML duplicate IP analysis and optional limited reference replacement. Python 3.10+, stdlib only."""
import argparse
import csv
import hashlib
import ipaddress
import json
import re
import sys
import tempfile
import os
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

PREFIXES = ('svb_host_', 'svb_', 'm1_', 'm2')
ADDRESS_TYPES = {'ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn'}

from xml_support import NoDTD, parse

def parse_config(data):
    root, config = parse(data)
    containers = [('shared', config.find('./shared/address'))]
    for device in config.findall('./devices/entry'):
        device_name = device.get('name')
        if not device_name:
            raise ValueError('Device entry has no name')
        for dg in device.findall('./device-group/entry'):
            if not dg.get('name'):
                raise ValueError('Device-group entry has no name')
            scope = 'device-group:' + device_name + '/' + dg.get('name')
            containers.append((scope, dg.find('./address')))
    # Reject namespaces / unfamiliar export layouts rather than claiming no duplicates.
    if not any(node is not None for _, node in containers):
        raise ValueError('No supported Shared/device-group address containers found')
    return containers

def normalize(kind, value):
    if '%' in value:
        raise ValueError('Scoped IPv6 addresses are unsupported')
    if kind == 'ip-netmask':
        net = ipaddress.ip_network(value, strict=False)
        first, last = net.network_address, net.broadcast_address
        label = str(first) if net.num_addresses == 1 else str(net)
        warning = ''
        if '/' in value and ipaddress.ip_interface(value).ip != first:
            warning = 'Host bits normalized for value comparison; original value retained'
    elif kind == 'ip-range':
        parts = value.split('-')
        if len(parts) != 2:
            raise ValueError('Expected start-end IP range')
        first, last = map(lambda v: ipaddress.ip_address(v.strip()), parts)
        if first.version != last.version or int(first) > int(last):
            raise ValueError('Invalid or mixed-family IP range')
        nets = list(ipaddress.summarize_address_range(first, last))
        label = str(first) if first == last else (str(nets[0]) if len(nets) == 1 else f'{first}-{last}')
        warning = ''
    else:
        raise ValueError('Unsupported address type')
    return (first.version, int(first), int(last)), label, warning

def rank(obj):
    penalized = obj['name'].casefold().startswith(PREFIXES)
    convention = False
    if obj['key'][1] == obj['key'][2] and '_' in obj['name']:
        hostname, suffix = obj['name'].rsplit('_', 1)
        # Syntactic hostname convention only; no DNS lookup or invented hostname scoring.
        if penalized:
            prefix = next((p for p in PREFIXES if hostname.casefold().startswith(p)), '')
            hostname = hostname[len(prefix):].lstrip('_')
        labels = hostname.split('.')
        valid = len(hostname) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', s) for s in labels)
        try:
            ipaddress.ip_address(hostname)
            valid = False
        except ValueError:
            pass
        try:
            convention = valid and ipaddress.ip_address(suffix) == ipaddress.ip_address(obj['key'][1] if obj['key'][0] == 4 else ipaddress.IPv6Address(obj['key'][1]))
        except ValueError:
            pass
    return (int(penalized), int(not convention))

def analyze(data):
    groups = defaultdict(list)
    inventory, issues = [], []
    skipped = Counter()
    identities = set()
    scopes_seen = set()
    for scope, container in parse_config(data):
        if scope in scopes_seen:
            raise ValueError('Repeated address scope')
        scopes_seen.add(scope)
        if container is None:
            continue
        for entry in container.findall('./entry'):
            name = entry.get('name')
            ident = (scope, name)
            if not name or ident in identities:
                raise ValueError(f'Missing or repeated object name in scope {scope}: {name!r}')
            identities.add(ident)
            types = [child for child in entry if child.tag in ADDRESS_TYPES]
            base = {'scope': scope, 'name': name, 'identity': [scope, name]}
            if len(types) != 1:
                issues.append({**base, 'issue': 'Expected exactly one recognized address type'})
                continue
            kind, value = types[0].tag, (types[0].text or '').strip()
            if kind not in ('ip-netmask', 'ip-range'):
                skipped[kind] += 1
                continue
            try:
                key, label, warning = normalize(kind, value)
            except ValueError as exc:
                issues.append({**base, 'type': kind, 'value': value, 'issue': str(exc)})
                continue
            obj = {**base, 'type': kind, 'value': value, 'key': key, 'ip': label,
                   'description': entry.findtext('./description', ''),
                   'tags': sorted(x.text or '' for x in entry.findall('./tag/member')),
                   'attributes': dict(entry.attrib),
                   'definition_xml': ET.tostring(entry, encoding='unicode')}
            obj['rank'] = rank(obj)
            inventory.append(obj)
            groups[key].append(obj)
            if warning:
                issues.append({**base, 'value': value, 'issue': warning})
    duplicates = []
    for key, objects in sorted(groups.items()):
        if len(objects) < 2:
            continue
        objects.sort(key=lambda o: (o['scope'], o['name']))
        best_rank = min(o['rank'] for o in objects)
        best = [o for o in objects if o['rank'] == best_rank]
        preferred = best[0] if len(best) == 1 else None
        duplicates.append({'ip': objects[0]['ip'], 'key': key,
            'preferred': preferred['identity'] if preferred else None,
            'status': 'selected' if preferred else 'needs_review',
            'reason': 'Unique best candidate by prefix penalty then hostname_IP' if preferred else 'Equal-ranked candidates; no tie-breaker specified',
            'best_candidates': [o['identity'] for o in best],
            'cross_scope': len({o['scope'] for o in objects}) > 1,
            'metadata_differs': len({(o['description'], tuple(o['tags'])) for o in objects}) > 1,
            'objects': objects})
    return {'version': '2.1', 'input_sha256': hashlib.sha256(data).hexdigest(),
        'summary': {'eligible_objects': len(inventory), 'duplicate_groups': len(duplicates),
                    'needs_review': sum(d['preferred'] is None for d in duplicates),
                    'skipped_types': dict(skipped), 'issues': len(issues)},
        'duplicates': duplicates, 'inventory': inventory, 'issues': issues,
        'replacement_authorized': False}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--replace', action='store_true', help='Write modified.xml and replacement_audit.json; input is never overwritten')
    parser.add_argument('--hierarchy', type=Path, help='Optional JSON device-group parent map when readonly hierarchy is absent')
    parser.add_argument('--output-dir', type=Path, default=Path('duplicate_analysis'))
    args = parser.parse_args(argv)
    try:
        data = args.config.read_bytes()
        report = analyze(data)
        modified = audit = None
        if args.replace:
            from replace_references import replace
            parent_map = json.loads(args.hierarchy.read_text(encoding='utf-8')) if args.hierarchy else None
            modified, audit = replace(data, report, parent_map)
        elif args.hierarchy:
            raise ValueError('--hierarchy requires --replace')
        targets = [args.output_dir / 'duplicates.csv', args.output_dir / 'analysis.json']
        if args.replace:
            targets += [args.output_dir / 'modified.xml', args.output_dir / 'replacement_audit.json']
        if any(p.resolve() == args.config.resolve() or p.exists() for p in targets):
            raise ValueError('Output exists or aliases input; choose a new output directory')
        if args.output_dir.exists():
            raise ValueError('Output directory already exists; choose a fresh directory')
        args.output_dir.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='panorama_stage_',dir=args.output_dir.parent) as stage:
            stage_dir=Path(stage)
            staged_targets=[stage_dir/p.name for p in targets]
            write_outputs(staged_targets, report, modified, audit)
            # Reserve destination exclusively only after every staged file is complete.
            args.output_dir.mkdir(exist_ok=False)
            try:
                for staged,target in zip(staged_targets,targets):
                    os.replace(staged,target)
            except OSError:
                for target in targets: target.unlink(missing_ok=True)
                args.output_dir.rmdir()
                raise
        print(json.dumps({'analysis': report['summary'], 'replacement': audit['summary'] if audit else None}, indent=2))
        return 0
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2

def write_outputs(targets, report, modified, audit):
        with targets[0].open('x', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(['IP', 'Preferred Object', 'Duplicate Objects'])
            for group in report['duplicates']:
                preferred = group['preferred']
                remaining = [o['identity'] for o in group['objects'] if o['identity'] != preferred]
                writer.writerow([group['ip'], json.dumps(preferred, ensure_ascii=False) if preferred else '', json.dumps(remaining, ensure_ascii=False)])
        with targets[1].open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
        if audit is not None:
            with targets[2].open('xb') as handle:
                handle.write(modified)
            with targets[3].open('x', encoding='utf-8') as handle:
                json.dump(audit, handle, indent=2, ensure_ascii=False)
                handle.write('\n')

if __name__ == '__main__':
    sys.exit(main())
