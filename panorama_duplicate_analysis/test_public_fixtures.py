"""Regression checks using pinned public Palo Alto Networks repository fixtures."""
import hashlib
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET
from analyze_duplicates import analyze
from replace_references import replace,signature

FIXTURES=Path(__file__).with_name('public_fixtures')

class PublicFixtureTests(unittest.TestCase):
    def test_original_upstream_samples(self):
        manifest=json.loads((FIXTURES/'verification_results.json').read_text())
        for expected in manifest['original_samples']:
            with self.subTest(file=expected['file']):
                data=(FIXTURES/expected['file']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(),expected['sha256'])
                report=analyze(data);out,audit=replace(data,report)
                self.assertEqual(report['summary'],expected['analysis'])
                self.assertEqual(audit['hierarchy_complete'],expected['hierarchy_complete'])
                self.assertEqual(out,data)
    def test_derived_public_replacement_case(self):
        data=(FIXTURES/'derived-replacement-case.xml').read_bytes()
        out,audit=replace(data,analyze(data))
        self.assertEqual(audit['summary']['replacements'],14)
        self.assertEqual(audit['summary']['collapsed_members'],8)
        self.assertEqual(audit['summary']['changed_lists'],7)
        self.assertEqual(replace(out,analyze(out))[0],out)
        before,after=ET.fromstring(data),ET.fromstring(out)
        # Independently compare all address definitions and every other rule family.
        self.assertEqual([signature(e) for e in before.findall('.//address/entry')],[signature(e) for e in after.findall('.//address/entry')])
        for family in ('nat','pbf','decryption','application-override','authentication','qos','dos'):
            self.assertEqual([signature(e) for e in before.findall('.//'+family)],[signature(e) for e in after.findall('.//'+family)])
        self.assertEqual([signature(e) for e in before.findall('.//dynamic')],[signature(e) for e in after.findall('.//dynamic')])
        self.assertEqual([signature(e) for e in before.findall('./readonly')],[signature(e) for e in after.findall('./readonly')])

if __name__=='__main__':unittest.main()
