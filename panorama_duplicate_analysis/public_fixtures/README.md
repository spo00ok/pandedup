# Public Panorama sample configuration verification

Source: Palo Alto Networks' pan-os-php repository:
https://github.com/PaloAltoNetworks/pan-os-php

Pinned commit: d87de874a289eca673dcdfa13903dd9a3e00f2d8

The five original XML files are copied byte-for-byte from the repository's
`tests/input` and `examples/sample-configs` directories. Their original paths,
versions, SHA-256 values, and observed results are in verification_results.json.
The upstream license is included in UPSTREAM_LICENSE.txt.

These are public example/test configurations, not production configuration
exports supplied by the user. They include example device settings and credential
fields from upstream; they are testing data, not deployable configurations.

All five parse. The four 8.0/8.1/10.0 test configurations contain five configured
device groups and five readonly hierarchy entries. Existing duplicate sets have
no unique winner under the configured preference rules, so they remain unchanged.
The 6.0 example lacks readonly hierarchy and receives no modifications.

`derived-replacement-case.xml` is explicitly a locally engineered test derivative
of panorama-10.0-merger.xml. It adds three address definitions using our naming
rules and adjusts sample member lists to exercise coexistence. It is not an
unchanged upstream export. It produces 14 substitutions across seven lists and
eight collapsed members; a second run is byte-identical. Its change provenance
and complete audit are included. No object definitions or non-target reference
locations are modified by the script.

To reproduce after extracting the package:

```bash
python -m unittest discover -s . -v
python analyze_duplicates.py public_fixtures/panorama-10.0-merger.xml --replace --output-dir upstream_results
python analyze_duplicates.py public_fixtures/derived-replacement-case.xml --replace --output-dir derived_results
```

Both output directory names must be fresh. The original sample is expected to
report unresolved preferences and zero replacements. The derived sample tests
actual modification behavior.

These older public configurations establish compatibility with independently
sourced Panorama XML structures. They do not establish production suitability,
current-version completeness, or successful PAN-OS commit/push validation.
