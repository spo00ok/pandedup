# Panorama duplicate address analysis and reference replacement — v2.1

Requires Python 3.10 or later. No third-party dependencies, API access, DNS queries, commits, or object deletion. Analysis is the default; optional replacement is described under Phase 2.

```bash
python analyze_duplicates.py panorama.xml --output-dir results_run1
```

Input: full exported Panorama `<config>` XML, optionally inside a successful XML API `<response><result>` wrapper. Partial address exports and namespaced XML are unsupported. Input bytes are read only. Existing output files are refused; choose a fresh directory.

Outputs:
- `duplicates.csv`: exactly `IP, Preferred Object, Duplicate Objects`.
- `analysis.json`: full eligible-object inventory, original address values and serialized definitions, ranking evidence, ties, excluded-type counts, invalid values, cross-scope flags, metadata differences, and input SHA-256.

CSV identities use JSON `[scope, name]` pairs to distinguish repeated names in different device groups. The duplicate column is a JSON array of pairs. A blank preferred field means unresolved; all candidates then appear in the duplicate column. Otherwise it contains the other candidates, excluding the preferred definition.

## Detection

Extracts concrete definitions at `/config/shared/address/entry` and `/config/devices/entry/device-group/entry/address/entry`. Inherited copies are not fabricated. Templates and local firewall/vsys definitions are outside this Panorama policy-object scope.

IPv4 and IPv6 `ip-netmask` and `ip-range` values are compared by exact IP family and inclusive start/end. Bare hosts equal /32 or /128 hosts. Equivalent IPv6 spellings match. Subnets with host bits are normalized using Python `ipaddress.ip_network(strict=False)` and flagged. Exactly equivalent ranges and subnets match; overlapping sets do not. Normalization is an analysis rule, not validation of PAN-OS acceptance in every configuration context.

FQDN and IP wildcard objects are explicitly counted as skipped. Wildcards can encode noncontiguous sets; wildcard equivalence is not implemented in this version. Invalid IP values are reported and excluded. Repeated names within one scope, malformed XML, failed API wrappers, and unsupported layouts fail loudly. DTDs are refused.

## Selection

1. Case-insensitive beginning-of-name penalty for `svb_host_`, `svb_`, `m1_`, `m2`. This covers the originally listed uppercase variants, including `M2_`; the broad `m2` match is intentional.
2. For a single host, prefer a syntactically valid hostname followed by `_` and an IP literal equal to the actual IP. Example: `c234.pcde-01_10.10.10.10`. When checking penalized candidates, strip one recognized legacy prefix from the hostname portion; the penalty still takes precedence.
3. If the best rank is shared, leave the preference unresolved. There is no alphabetical, Shared-scope, reference-count, DNS, or subjective “meaningful hostname” tie-breaker.

Subnet/range candidates receive only the prefix preference until subnet naming rules are supplied. The output contains existing objects only; no names are generated.

Equal IP sets do not prove that definitions are interchangeable. Tags can influence dynamic address groups, descriptions/attributes can differ, and overrides can change what a name resolves to. Cross-scope recommendations are global naming recommendations, not an authorized replacement map. Phase 2 must independently resolve visibility, inheritance, overrides, and all supported reference contexts. No hierarchy or reference analysis is performed here.

## Requirements retained for later phases

- Never delete any duplicate address definition.
- Never perform blind text replacements.
- Inventory and audit references, including unusual locations.
- Respect scope, inheritance, and overrides before each replacement.
- Preserve original XML; output any future modifications separately.
- Validate intended replacements and detect unrelated changes.
- Leave uncertain references untouched and report them.
- Subnet preferences and tie-breakers remain pending.

## Verification

```bash
python -m unittest discover -s . -v
```

Tests cover prefix precedence, naming conventions, case handling, all-penalized groups, ties, scoped identities, host/subnet/range/IPv6 normalization, overlap exclusion, invalid values, excluded types, XML wrappers, DTD rejection, and repeated identities. Synthetic tests establish implemented behavior; a real Panorama export has not yet been supplied or validated.

## Verified references

- Palo Alto Networks, Shared/device-group policy objects and inheritance: https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/create-objects-for-use-in-shared-or-device-group-policy
- Palo Alto Networks open-source SDK source: `AddressObject`, `/address`, entry suffix, supported type nodes, description and tag/member paths: https://pan-os-python.readthedocs.io/en/latest/_modules/panos/objects.html#AddressObject
- Python standard-library IP parsing and normalization: https://docs.python.org/3/library/ipaddress.html

The implementation is original code; it uses the SDK source to verify the object structure, without requiring the SDK or inventing an offline SDK loader.

# Phase 2 — limited reference replacement (v2.1)

Analysis-only invocation still works unchanged. To generate modified XML:

```bash
python analyze_duplicates.py panorama.xml --replace --output-dir results_run2
```

The same directory receives `duplicates.csv`, `analysis.json`, `modified.xml`, and `replacement_audit.json`. No upload, commit, deletion, or modification of the input occurs. `replacement_authorized: false` in the original analysis report means the duplicate report alone is not a replacement map; only the scope-validated replacement engine authorizes individual changes.

## Exact modification scope

Only these lists beneath Shared and device-group scopes are eligible:
- `address-group/entry/static/member`
- `{pre-rulebase,post-rulebase,rulebase}/security/rules/entry/source/member`
- `{pre-rulebase,post-rulebase,rulebase}/security/rules/entry/destination/member`

Local rulebase lists are supported if present under these same scopes. Local firewall/vsys and template policy are not edited. NAT, every other policy family, dynamic filters, network settings, descriptions, tags, rule attributes, negation, and address definitions remain unchanged structurally.

Each permitted list retains its original order. Repeated members are collapsed only for preferred names introduced by at least one successful replacement in that list; unrelated pre-existing repeated members stay intact. First occurrence wins. Source and destination are separate lists. Group names and rule names are never renamed.

## Hierarchy and effective values

The implementation reads device-group parent metadata from `/config/readonly/devices/entry/device-group/entry/parent-dg`. An explicitly present metadata entry without a parent indicates a top-level group. Missing entries do NOT imply a flat hierarchy. Every configured device group must have a known parent chain reaching Shared. Missing metadata disables all edits, including Shared edits, because descendants cannot be checked safely.

If the export omits readonly hierarchy, supply a complete map with scoped identities:

```json
{
  "device-group:localhost.localdomain/Parent": "shared",
  "device-group:localhost.localdomain/Child": "device-group:localhost.localdomain/Parent"
}
```

```bash
python analyze_duplicates.py panorama.xml --replace --hierarchy hierarchy.json --output-dir results_run3
```

The map is an explicit assertion of hierarchy, not inferred from object names. Unknown parents, cycles, and contradictions with available XML metadata fail. Stale readonly groups not present in the configured scopes also fail rather than being ignored.

Replacement uses uniquely selected phase-1 preferences. It never invents a fallback if the preferred object is inaccessible or the selection tied. Both names must resolve to address objects with the SAME address type and normalized IP set in the list's scope AND every configured descendant scope. Equivalent range/netmask groups remain detectable but cross-type replacements are deliberately refused. A same-name override with a different type/value blocks replacement, irrespective of default or ancestor-first precedence. Namespace collisions with groups, regions, or external lists also block replacement. IP-literal names and `any` are treated conservatively and never substituted.

All configured descendants are checked, including ones where a rule/group override might make the parent list unused; this may skip more than necessary but avoids assuming effective policy behavior. Local firewall overrides and future configuration changes cannot be established from an offline Panorama-only export.

## Audit and validation

`replacement_audit.json` records each list's before/after members, each substitution, each collapsed member, the preferred identity, checked descendant scopes, and skip reasons. Member indexes are zero-based. It includes input/output SHA-256 and an exact-match scan of original element text and attribute values for duplicate names. This occurrence scan includes definitions and incidental matches; it is not an exhaustive parser of embedded expressions and does not authorize edits outside the allowed lists.

Before writing, the engine compares the entire original and modified XML trees while masking ONLY changed list children. It maps Expat parser byte offsets to parsed original XML member nodes and patches only those member contents/removals. It reparses patched bytes and compares them with the intended tree. This verifies preservation outside the edited lists and retention of all address definitions. Original formatting, XML declaration, quote styles, unrelated CDATA, comments and processing instructions (including outside the root) are preserved. Replacement text is XML-escaped. Modification supports UTF-8/ASCII exports only; other XML encodings remain available for analysis but fail explicitly if edits are needed. If no edits are made, output bytes equal input bytes exactly.

The output directory must not already exist. All files are written to a temporary staging directory before the destination is reserved and populated. Failed staging leaves no destination or partial reports; ordinary publication failures roll back this run's output. Abrupt process or host termination during publication is not a filesystem transaction.

Offline structural validation is not a PAN-OS commit validation. This version has synthetic and CLI verification; no actual user export or live Panorama commit has been tested.

## Additional verified sources

- PAN-OS SDK Shared/device-group and rulebase structure: https://pan-os-python.readthedocs.io/en/latest/_modules/panos/panorama.html
- Palo Alto KB showing readonly hierarchy and parent-dg metadata: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000g206CAA&lang=en_US
- Configurable inherited-object precedence: https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-precedence-of-inherited-objects

These sources establish why hierarchy and conflicting overrides must be treated explicitly; the XML engine is original code using Python's standard library.

## End-to-end review (v2.1)

The review added strict successful API-wrapper validation, duplicate-singleton and nested-value rejection, stale-analysis hash validation, mixed static/dynamic and mixed-content list exclusion, device-group-only scope support, explicit malformed-hierarchy handling, surgical XML patching, and staged output publication.

The suite includes 43 named tests and 100 generated hierarchy cases with an independent effective-address-set check for both precedence orders. A synthetic scale run with 10,000 address definitions, 5,000 duplicate sets, and 5,000 reference replacements passed in about 3.7 seconds on the review environment; this is an observation rather than a performance guarantee. Tests also cover CLI output, audit hashes, overwrite refusal, failed staging cleanup, and byte-identical second-run output.

## Independently sourced public configurations

The package now includes five byte-identical public Panorama XML samples from
Palo Alto Networks' pan-os-php repository at pinned commit
`d87de874a289eca673dcdfa13903dd9a3e00f2d8`, plus the upstream license and source/hash
manifest. See `public_fixtures/README.md` for source paths and reproducible commands.

All original samples parse successfully. Their ambiguous duplicate preferences
correctly remain unresolved. A clearly labeled derived test adds names matching
our preference rules and coexisting references: 14 replacements, eight collapsed
members, seven changed lists, intact address definitions and unchanged other
policy families, and a byte-identical second run. The full suite now has 45 named
tests, including a subtest for each original public XML sample.

The earlier synthetic-only verification limit is superseded by these public
fixture runs. A production export and live PAN-OS validation remain untested.
