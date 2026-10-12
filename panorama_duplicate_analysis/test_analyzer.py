import unittest
from analyze_duplicates import analyze, normalize, parse_config

def config(entries, other=''):
    return f'<config><shared><address>{entries}</address></shared>{other}</config>'.encode()

def obj(name, value, kind='ip-netmask'):
    return f'<entry name="{name}"><{kind}>{value}</{kind}></entry>'

class Tests(unittest.TestCase):
    def test_prefix_overrides_convention(self):
        r = analyze(config(obj('svb_host_pc_10.10.10.10','10.10.10.10')+obj('pc','10.10.10.10/32')))
        self.assertEqual(r['duplicates'][0]['preferred'], ['shared','pc'])
    def test_convention(self):
        r = analyze(config(obj('pc.example_10.10.10.10','10.10.10.10')+obj('other','10.10.10.10')))
        self.assertEqual(r['duplicates'][0]['preferred'][1], 'pc.example_10.10.10.10')
    def test_short_legacy_name(self):
        r=analyze(config(obj('svb_old','10.0.0.1')+obj('pc_10.0.0.1','10.0.0.1')))
        self.assertEqual(r['duplicates'][0]['preferred'][1],'pc_10.0.0.1')
    def test_tie(self):
        r = analyze(config(obj('a','10.0.0.1')+obj('b','10.0.0.1')))
        self.assertIsNone(r['duplicates'][0]['preferred'])
    def test_cross_scope(self):
        dg='<devices><entry name="localhost.localdomain"><device-group><entry name="dg"><address>'+obj('a','10.0.0.1')+'</address></entry></device-group></entry></devices>'
        r=analyze(config(obj('a','10.0.0.1'),dg))
        self.assertTrue(r['duplicates'][0]['cross_scope'])
        self.assertIsNone(r['duplicates'][0]['preferred'])
    def test_normalization(self):
        self.assertEqual(normalize('ip-netmask','10.0.0.9/24')[0], normalize('ip-range','10.0.0.0-10.0.0.255')[0])
        self.assertEqual(normalize('ip-netmask','2001:db8::1/128')[0],normalize('ip-netmask','2001:0db8::1')[0])
    def test_no_overlap_grouping(self):
        r=analyze(config(obj('a','10.0.0.0/24')+obj('b','10.0.0.0/25')))
        self.assertEqual(r['duplicates'],[])
    def test_invalid_and_excluded(self):
        r=analyze(config(obj('bad','999.1.1.1')+obj('dns','example.com','fqdn')))
        self.assertEqual(len(r['issues']),1)
        self.assertEqual(r['summary']['skipped_types'],{'fqdn':1})
    def test_dtd(self):
        with self.assertRaises(ValueError):
            parse_config(b'<!DOCTYPE config [<!ENTITY x "10.0.0.1">]><config><shared><address/></shared></config>')
    def test_wrapper_and_failures(self):
        self.assertEqual(analyze(b'<response status="success"><result>'+config(obj('a','10.0.0.1'))+b'</result></response>')['summary']['eligible_objects'],1)
        with self.assertRaises(ValueError): analyze(b'<response status="error"/>')
        with self.assertRaises(ValueError): analyze(b'<address/>')
    def test_duplicate_identity(self):
        with self.assertRaises(ValueError): analyze(config(obj('a','10.0.0.1')+obj('a','10.0.0.2')))
    def test_all_penalized_and_case(self):
        r=analyze(config(obj('SVB_pc_10.0.0.1','10.0.0.1')+obj('M2_old','10.0.0.1')))
        self.assertEqual(r['duplicates'][0]['preferred'][1],'SVB_pc_10.0.0.1')

if __name__=='__main__': unittest.main()
