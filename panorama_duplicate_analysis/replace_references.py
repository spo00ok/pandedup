"""Conservative replacement engine; only Static groups and Security address lists."""
import copy
import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from analyze_duplicates import normalize
from xml_support import parse as parse_xml, patch_members
from functools import lru_cache


def parse(data):
    return parse_xml(data,preserve=True)


def signature(node):
    return (node.tag, tuple(sorted(node.attrib.items())), node.text if node.text and node.text.strip() else '',
            node.tail if node.tail and node.tail.strip() else '',
            tuple(signature(c) for c in node))


def scope_nodes(config):
    scopes = {'shared':ET.Element('shared')}
    shared = config.find('./shared')
    if shared is not None:
        scopes['shared'] = shared
    for device in config.findall('./devices/entry'):
        for dg in device.findall('./device-group/entry'):
            scope = f"device-group:{device.get('name')}/{dg.get('name')}"
            if scope in scopes:
                raise ValueError('Repeated device-group scope')
            scopes[scope] = dg
    return scopes


def hierarchy(config, scopes, supplied=None):
    """Never infer absent metadata to mean a flat hierarchy."""
    parents = {'shared': None}
    metadata = {}
    for dev in config.findall('./readonly/devices/entry'):
        for dg in dev.findall('./device-group/entry'):
            scope = f"device-group:{dev.get('name')}/{dg.get('name')}"
            if scope in metadata:
                raise ValueError('Repeated hierarchy entry')
            p = (dg.findtext('./parent-dg') or '').strip()
            metadata[scope] = f"device-group:{dev.get('name')}/{p}" if p and p != 'shared' else 'shared'
    selected = supplied if supplied is not None else metadata
    if not isinstance(selected, dict):
        raise ValueError('Hierarchy must be a JSON object: scoped device-group -> scoped parent or shared')
    for scope, parent in selected.items():
        if not isinstance(scope,str) or not isinstance(parent,str):
            raise ValueError('Hierarchy keys and parent values must be strings')
        if scope not in scopes or scope == 'shared' or parent not in scopes or parent == scope:
            raise ValueError(f'Invalid hierarchy edge: {scope!r} -> {parent!r}')
        if supplied is not None and scope in metadata and parent != metadata[scope]:
            raise ValueError('Supplied hierarchy conflicts with XML readonly metadata')
        parents[scope] = parent
    for scope in scopes:
        seen = set()
        current = scope
        while current is not None and current in parents:
            if current in seen:
                raise ValueError('Cycle in device-group hierarchy')
            seen.add(current)
            current = parents[current]
    complete = all(scope in parents for scope in scopes)
    return parents, complete


def lists(scopes):
    for scope, node in scopes.items():
        for group in node.findall('./address-group/entry'):
            static = group.find('./static')
            if static is not None:
                yield scope, 'static-address-group', group.get('name'), 'static', static
        for rb in ('pre-rulebase', 'post-rulebase', 'rulebase'):
            for rule in node.findall(f'./{rb}/security/rules/entry'):
                for field in ('source', 'destination'):
                    parent = rule.find('./' + field)
                    if parent is not None:
                        yield scope, 'security', rule.get('name'), rb + '/' + field, parent


def replace(data, report, supplied_hierarchy=None):
    if report.get('input_sha256') != hashlib.sha256(data).hexdigest():
        raise ValueError('Analysis report does not match input XML')
    root, config = parse(data)
    scopes = scope_nodes(config)
    parents, complete = hierarchy(config, scopes, supplied_hierarchy)
    definitions = {}
    for scope, node in scopes.items():
        for category in ('address', 'address-group', 'region', 'external-list'):
            for entry in node.findall(f'./{category}/entry'):
                name = entry.get('name')
                if not name or (scope, name) in definitions:
                    raise ValueError(f'Missing or ambiguous address namespace definition: {scope}, {name}')
                types = [c for c in entry if c.tag in ('ip-netmask','ip-range','fqdn','ip-wildcard')]
                key = None
                kind = None
                if category == 'address' and len(types) == 1:
                    kind = types[0].tag
                    if kind in ('ip-netmask','ip-range'):
                        try:
                            key = normalize(kind,(types[0].text or '').strip())[0]
                        except ValueError:
                            pass
                definitions[(scope,name)] = (category, kind, key)
    mapping = {}
    for group in report['duplicates']:
        if group['preferred']:
            for obj in group['objects']:
                ident = tuple(obj['identity'])
                if ident != tuple(group['preferred']):
                    mapping[ident] = tuple(group['preferred'])
    @lru_cache(maxsize=None)
    def chain(scope):
        result = []
        while scope is not None:
            if scope not in parents:
                return None
            result.append(scope)
            scope = parents[scope]
        return result
    @lru_cache(maxsize=None)
    def resolve(scope, name):
        path = chain(scope)
        if path is None:
            return None, 'Incomplete hierarchy'
        matches = [(s,name) for s in path if (s,name) in definitions]
        if not matches:
            return None, 'Name is not visible'
        # Avoid assuming default vs ancestor-first precedence. Same-name differing
        # definitions are left untouched regardless of the Panorama setting.
        values = {definitions[i] for i in matches}
        if len(values) != 1:
            return None, 'Conflicting inherited definitions or namespace collision'
        return matches[0], None
    audit = {'version':'2.1','input_sha256':hashlib.sha256(data).hexdigest(),
             'hierarchy_complete':complete,'changes':[],'skipped':[],
             'occurrences':[], 'validation':{}}
    original = copy.deepcopy(root)
    target_members = set()
    eligible = list(lists(scopes))
    contexts_seen = set()
    for scope,category,owner,field,parent in eligible:
        ident = (scope,category,owner,field)
        if not owner or ident in contexts_seen:
            raise ValueError('Missing or repeated target list owner identity')
        contexts_seen.add(ident)
    for scope, category, owner, field, parent in eligible:
        members = parent.findall('./member')
        target_members.update(id(m) for m in members)
        context = {'scope':scope,'category':category,'owner':owner,'field':field}
        if not complete:
            audit['skipped'].append({**context,'reason':'Incomplete hierarchy; all modifications disabled'})
            continue
        if category=='static-address-group' and any(g.get('name')==owner and g.find('./dynamic') is not None for g in scopes[scope].findall('./address-group/entry')):
            audit['skipped'].append({**context,'reason':'Group contains both static and dynamic definitions'})
            continue
        if ((parent.text or '').strip() or any((m.tail or '').strip() for m in members)
                or any(m.attrib or len(m) for m in members) or any(c.tag != 'member' for c in parent)):
            audit['skipped'].append({**context,'reason':'Unexpected member-list structure'})
            continue
        contexts = [s for s in scopes if scope in (chain(s) or [])]
        before = [m.text or '' for m in members]
        after = list(before)
        events = []
        changed_names = set()
        for index, name in enumerate(before):
            if name == 'any':
                continue
            try:
                ipaddress.ip_network(name,strict=False)
                audit['skipped'].append({**context,'name':name,'reason':'IP literal/object-name ambiguity'})
                continue
            except ValueError:
                pass
            old, error = resolve(scope,name)
            if old not in mapping:
                if error and any(i[1] == name for i in mapping):
                    audit['skipped'].append({**context,'name':name,'reason':error})
                continue
            preferred = mapping[old]
            new_name = preferred[1]
            if name == new_name:
                continue
            if new_name == 'any':
                audit['skipped'].append({**context,'name':name,'reason':'Reserved preferred name any'})
                continue
            try:
                ipaddress.ip_network(new_name,strict=False)
                audit['skipped'].append({**context,'name':name,'reason':'Preferred name is an IP literal'})
                continue
            except ValueError:
                pass
            reason = None
            for effective_scope in contexts:
                old_eff, err1 = resolve(effective_scope,name)
                new_eff, err2 = resolve(effective_scope,new_name)
                if err1 or err2:
                    reason = f'{effective_scope}: {err1 or err2}'
                    break
                if preferred[0] not in chain(effective_scope):
                    reason = 'Preferred definition is outside visible scope'
                    break
                a,b = definitions[old_eff], definitions[new_eff]
                if a[0] != 'address' or b[0] != 'address' or a[2] is None or a != b:
                    reason = f'{effective_scope}: type/value differs or resolves to non-address'
                    break
            if reason:
                audit['skipped'].append({**context,'name':name,'preferred':preferred,'reason':reason})
                continue
            after[index] = new_name
            changed_names.add(new_name)
            events.append({'action':'replace','member_index':index,'old':name,'new':new_name,'preferred_identity':preferred})
        if not events:
            continue
        seen = set()
        final = []
        for index,(member,name) in enumerate(zip(members,after)):
            if name in changed_names and name in seen:
                parent.remove(member)
                events.append({'action':'collapse','member_index':index,'old':before[index],'new':name})
            else:
                if name != before[index]:
                    member.text = name
                seen.add(name)
                final.append(name)
        audit['changes'].append({**context,'before':before,'after':final,'events':events,'checked_scopes':contexts})
    # Whole-XML occurrence discovery is read-only and deliberately not a replacement rule.
    duplicate_names = {o['name'] for g in report['duplicates'] for o in g['objects']}
    def walk(node, path):
        if not isinstance(node.tag,str):
            return
        segment = node.tag + (f'[@name={node.get("name")!r}]' if node.get('name') is not None else '')
        here = path + '/' + segment
        values = [('text',node.text or '')] + [('@'+k,v) for k,v in node.attrib.items()]
        for location,value in values:
            if value in duplicate_names:
                audit['occurrences'].append({'path':here,'location':location,'name':value,
                    'classification':'allowed_member' if id(node) in target_members and location=='text' else 'outside_modification_scope'})
        for child in node:
            walk(child,here)
    discovery_config = original if original.tag == 'config' else original.find('./result/config')
    target_members = {id(m) for *_,parent in lists(scope_nodes(discovery_config)) for m in parent.findall('./member')}
    walk(discovery_config,'')
    # Validate a masked COPY; the output tree remains untouched.
    masked = copy.deepcopy(root)
    masked_config = masked if masked.tag == 'config' else masked.find('./result/config')
    original_config = original if original.tag == 'config' else original.find('./result/config')
    changed_contexts = {(c['scope'],c['category'],c['owner'],c['field']) for c in audit['changes']}
    for tree_config in (masked_config, original_config):
        for scope,cat,owner,field,parent in lists(scope_nodes(tree_config)):
            if (scope,cat,owner,field) in changed_contexts:
                parent.text = None
                for child in list(parent):
                    parent.remove(child)
    if signature(masked) != signature(original):
        raise ValueError('Validation: unexpected change outside permitted lists')
    pristine, _ = parse(data)
    edits = []
    change_map = {(c['scope'],c['category'],c['owner'],c['field']):c for c in audit['changes']}
    pristine_config = pristine if pristine.tag=='config' else pristine.find('./result/config')
    for scope,cat,owner,field,parent in lists(scope_nodes(pristine_config)):
        change = change_map.get((scope,cat,owner,field))
        if change:
            events = change['events']
            replacements = {e['member_index']:e['new'] for e in events if e['action']=='replace'}
            removals = {e['member_index'] for e in events if e['action']=='collapse'}
            for index,member in enumerate(parent.findall('./member')):
                if index in removals: edits.append((member,None))
                elif index in replacements: edits.append((member,replacements[index]))
    out = patch_members(data,pristine,edits) if edits else data
    reparsed_root, reparsed_config = parse(out)
    if signature(reparsed_root) != signature(root):
        raise ValueError('Validation: serialized XML differs from intended tree')
    if not audit['changes']:
        out = data
    audit['output_sha256'] = hashlib.sha256(out).hexdigest()
    audit['summary'] = {'changed_lists':len(audit['changes']),
        'replacements':sum(e['action']=='replace' for c in audit['changes'] for e in c['events']),
        'collapsed_members':sum(e['action']=='collapse' for c in audit['changes'] for e in c['events']),
        'skipped':len(audit['skipped'])}
    audit['validation'] = {'outside_target_lists_unchanged':True,'all_address_definitions_retained':True,
        'xml_reparsed':parse(out)[1] is not None}
    return out,audit
