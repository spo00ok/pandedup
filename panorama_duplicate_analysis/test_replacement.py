import unittest
import xml.etree.ElementTree as ET
from analyze_duplicates import analyze
from replace_references import replace, signature
from test_analyzer import obj

OLD='svb_old'
NEW='pc_10.0.0.1'
def members(*names): return ''.join(f'<member>{n}</member>' for n in names)
def group(*names): return '<address-group><entry name="g"><static>'+members(*names)+'</static></entry></address-group>'
def security(*names): return '<pre-rulebase><security><rules><entry name="r"><source>'+members(*names)+'</source><destination>'+members(OLD)+'</destination><negate-source>yes</negate-source></entry></rules></security></pre-rulebase>'
def xml(shared, dg='', readonly=''): return ('<config><shared>'+shared+'</shared>'+dg+readonly+'</config>').encode()
def defs(): return '<address>'+obj(OLD,'10.0.0.1')+obj(NEW,'10.0.0.1')+'</address>'
def dg(name,body): return '<devices><entry name="localhost.localdomain"><device-group><entry name="'+name+'">'+body+'</entry></device-group></entry></devices>'
S='device-group:localhost.localdomain/'
class ReplacementTests(unittest.TestCase):
    def run_replace(self,data,h=None): return replace(data,analyze(data),h)
    def test_coexistence_and_security_lists(self):
        data=xml(defs()+group(OLD,NEW,OLD,'unrelated')+security(OLD,NEW))
        out,a=self.run_replace(data)
        root=ET.fromstring(out)
        self.assertEqual([m.text for m in root.findall('./shared/address-group/entry/static/member')],[NEW,'unrelated'])
        self.assertEqual([m.text for m in root.findall('.//security/rules/entry/source/member')],[NEW])
        self.assertEqual([m.text for m in root.findall('.//security/rules/entry/destination/member')],[NEW])
        self.assertEqual(root.findtext('.//negate-source'),'yes')
        self.assertEqual(a['summary']['collapsed_members'],3)
        self.assertEqual(signature(root.find('./shared/address')),signature(ET.fromstring(data).find('./shared/address')))
    def test_other_paths_and_comments_preserved(self):
        extra='<post-rulebase><nat><rules><entry name="n"><source>'+members(OLD)+'</source></entry></rules></nat></post-rulebase><!--keep--><?instruction keep?><description>svb_old</description><address-group><entry name="dyn"><dynamic><filter>svb_old</filter></dynamic></entry></address-group>'
        out,a=self.run_replace(xml(defs()+security(OLD)+extra))
        self.assertEqual(ET.fromstring(out).findtext('.//nat/rules/entry/source/member'),OLD)
        self.assertIn(b'<!--keep-->',out); self.assertIn(b'<?instruction keep?>',out)
        self.assertEqual(ET.fromstring(out).findtext('.//dynamic/filter'),OLD)
    def test_missing_hierarchy_disables(self):
        data=xml(defs()+group(OLD),dg('a',security(OLD)))
        out,a=self.run_replace(data)
        self.assertEqual(out,data); self.assertFalse(a['hierarchy_complete'])
    def test_shared_inheritance(self):
        data=xml(defs(),dg('a',security(OLD)))
        out,a=self.run_replace(data,{S+'a':'shared'})
        self.assertEqual(a['summary']['replacements'],2)
    def test_sibling_not_visible(self):
        device='<devices><entry name="localhost.localdomain"><device-group><entry name="a"><address>'+obj(OLD,'10.0.0.1')+'</address>'+security(OLD)+'</entry><entry name="b"><address>'+obj(NEW,'10.0.0.1')+'</address></entry></device-group></entry></devices>'
        data=xml('<address/>',device)
        out,a=self.run_replace(data,{S+'a':'shared',S+'b':'shared'})
        self.assertEqual(out,data); self.assertTrue(a['skipped'])
    def test_descendant_override_blocks_parent_edit(self):
        data=xml(defs()+group(OLD),dg('a','<address>'+obj(NEW,'10.0.0.2')+'</address>'))
        out,a=self.run_replace(data,{S+'a':'shared'})
        self.assertEqual(out,data)
        self.assertTrue(any('Conflicting' in s['reason'] for s in a['skipped']))
    def test_all_same_override_safe(self):
        data=xml(defs()+group(OLD),dg('a','<address>'+obj(OLD,'10.0.0.1')+'</address>'))
        out,a=self.run_replace(data,{S+'a':'shared'})
        self.assertEqual(a['summary']['replacements'],1)
    def test_tie_untouched(self):
        data=xml('<address>'+obj('a','10.0.0.1')+obj('b','10.0.0.1')+'</address>'+group('a','b'))
        out,a=self.run_replace(data); self.assertEqual(out,data)
    def test_unrelated_repetition_untouched(self):
        out,a=self.run_replace(xml(defs()+group(OLD,'unrelated','unrelated')))
        self.assertEqual([m.text for m in ET.fromstring(out).findall('.//static/member')],[NEW,'unrelated','unrelated'])
    def test_cycle_rejected(self):
        device='<devices><entry name="localhost.localdomain"><device-group><entry name="a"/><entry name="b"/></device-group></entry></devices>'
        with self.assertRaises(ValueError): self.run_replace(xml(defs(),device),{S+'a':S+'b',S+'b':S+'a'})
    def test_readonly_hierarchy(self):
        ro='<readonly><devices><entry name="localhost.localdomain"><device-group><entry name="a"/></device-group></entry></devices></readonly>'
        out,a=self.run_replace(xml(defs(),dg('a',security(OLD)),ro))
        self.assertEqual(a['summary']['replacements'],2)
    def test_group_collision_blocks(self):
        data=xml(defs(),dg('a','<address-group><entry name="'+NEW+'"><static>'+members(OLD)+'</static></entry></address-group>'+security(OLD)))
        out,a=self.run_replace(data,{S+'a':'shared'}); self.assertEqual(out,data)
    def test_second_run_idempotent(self):
        out,a=self.run_replace(xml(defs()+group(OLD,NEW)+security(OLD)))
        twice,b=self.run_replace(out); self.assertEqual(out,twice); self.assertEqual(b['summary']['replacements'],0)

if __name__=='__main__': unittest.main()
