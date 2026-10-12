"""Additional adversarial, independent-behavior and full CLI verification."""
import csv
import hashlib
import json
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import xml.etree.ElementTree as ET
from analyze_duplicates import analyze
from replace_references import replace,signature
from test_replacement import xml,defs,group,security,members,dg,obj,OLD,NEW,S

class ReviewTests(unittest.TestCase):
    def test_mixed_group_unchanged(self):
        data=xml(defs()+'<address-group><entry name="g"><static>'+members(OLD)+'</static><dynamic><filter>x</filter></dynamic></entry></address-group>')
        out,a=replace(data,analyze(data));self.assertEqual(out,data)
        self.assertIn('both static and dynamic',a['skipped'][0]['reason'])
    def test_surgical_bytes(self):
        data=b'<?xml version="1.0" encoding="UTF-8"?>\r\n<!--outside-->\r\n'+xml(defs()+group(OLD)+'<description><![CDATA[<keep>  spaces </keep>]]></description>').replace(b'<entry name="g">',b"<entry name='g' attr='a > b'>")+b'\r\n<?after keep?>'
        out,a=replace(data,analyze(data))
        expected=data.replace(b'<member>svb_old</member>',b'<member>pc_10.0.0.1</member>')
        self.assertEqual(out,expected)
    def test_unicode_and_entity_name(self):
        new='clean & nice'
        data=xml('<address>'+obj(OLD,'10.0.0.1')+obj('clean &amp; nice','10.0.0.1')+'</address>'+group(OLD))
        out,a=replace(data,analyze(data));self.assertEqual(ET.fromstring(out).findtext('.//static/member'),new)
    def test_stale_report_rejected(self):
        data=xml(defs()+group(OLD));r=analyze(data);r['input_sha256']='wrong'
        with self.assertRaises(ValueError): replace(data,r)
    def test_duplicate_fields_rejected(self):
        data=xml(defs()+'<pre-rulebase><security><rules><entry name="r"><source>'+members(OLD)+'</source><source>'+members(OLD)+'</source></entry></rules></security></pre-rulebase>')
        with self.assertRaises(ValueError):analyze(data)
    def test_nested_value_rejected(self):
        with self.assertRaises(ValueError):analyze(xml('<address><entry name="a"><ip-netmask>10.0.0.1<x/></ip-netmask></entry></address>'))
    def test_error_wrapper_direct(self):
        data=b'<response status="error"><result>'+xml(defs())+b'</result></response>'
        with self.assertRaises(ValueError):replace(data,{'input_sha256':hashlib.sha256(data).hexdigest()})
    def test_dg_only_scope(self):
        data=b'<config>'+dg('a',defs()+security(OLD)).encode()+b'</config>'
        out,a=replace(data,analyze(data),{S+'a':'shared'});self.assertEqual(a['summary']['replacements'],2)
    def test_bad_hierarchy_value(self):
        data=xml(defs(),dg('a',security(OLD)))
        with self.assertRaises(ValueError):replace(data,analyze(data),{S+'a':[]})
    def test_multilevel_conflict(self):
        device='<devices><entry name="localhost.localdomain"><device-group><entry name="parent">'+security(OLD)+'</entry><entry name="child"><address>'+obj(NEW,'10.0.0.2')+'</address></entry></device-group></entry></devices>'
        data=xml(defs(),device)
        out,a=replace(data,analyze(data),{S+'parent':'shared',S+'child':S+'parent'})
        self.assertEqual(out,data)
    def test_post_and_local(self):
        for rb in ('post-rulebase','rulebase'):
            data=xml(defs()+security(OLD).replace('pre-rulebase',rb))
            out,a=replace(data,analyze(data));self.assertEqual(a['summary']['replacements'],2)
    def test_ipv6_and_range(self):
        for kind,value in [('ip-netmask','2001:db8::1'),('ip-range','10.0.0.1-10.0.0.3')]:
            data=xml('<address>'+obj(OLD,value,kind)+obj('clean',value,kind)+'</address>'+group(OLD))
            out,a=replace(data,analyze(data));self.assertEqual(a['summary']['replacements'],1)
    def test_cross_type_refused(self):
        data=xml('<address>'+obj(OLD,'10.0.0.1-10.0.0.1','ip-range')+obj(NEW,'10.0.0.1')+'</address>'+group(OLD))
        out,a=replace(data,analyze(data));self.assertEqual(out,data)
    def test_randomized_effective_address_sets(self):
        # Independent oracle evaluates inherited Shared rules in each leaf using
        # both descendant-first and ancestor-first object precedence.
        for seed in range(100):
            rng=random.Random(seed)
            leaf_values=[rng.choice([None,'10.0.0.1','10.0.0.2']) for _ in range(3)]
            entries=''.join('<entry name="d'+str(i)+'">'+('<address>'+obj(NEW,value)+'</address>' if value else '')+'</entry>' for i,value in enumerate(leaf_values))
            data=xml(defs()+security(OLD,NEW),'<devices><entry name="localhost.localdomain"><device-group>'+entries+'</device-group></entry></devices>')
            out,a=replace(data,analyze(data),{S+'d'+str(i):'shared' for i in range(3)})
            def effective(blob,leaf,ancestor_first):
                root=ET.fromstring(blob);scopes=[root.find('./shared'),root.find('./devices/entry/device-group/entry[@name="d'+str(leaf)+'"]')]
                if not ancestor_first:scopes.reverse()
                def value(name):
                    for scope in scopes:
                        for e in scope.findall('./address/entry'):
                            if e.get('name')==name:return e.findtext('./ip-netmask')
                    raise AssertionError('Unresolved reference')
                return {value(m.text) for m in root.findall('./shared/pre-rulebase/security/rules/entry/source/member')}
            for leaf in range(3):
                for precedence in (False,True):self.assertEqual(effective(data,leaf,precedence),effective(out,leaf,precedence))
    def test_mixed_content_list_unchanged(self):
        data=xml(defs()+group(OLD).replace('<static>','<static>unexpected'))
        out,a=replace(data,analyze(data));self.assertEqual(out,data)
    def test_utf16_analysis_but_no_modification(self):
        data=xml(defs()+group(OLD)).decode().encode('utf-16')
        report=analyze(data)
        with self.assertRaises(ValueError):replace(data,report)
    def test_staged_write_failure_leaves_no_output(self):
        import analyze_duplicates
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'config.xml';data=xml(defs()+group(OLD));source.write_bytes(data)
            output=Path(temp)/'output'
            with patch('analyze_duplicates.write_outputs',side_effect=OSError('simulated disk failure')):
                result=analyze_duplicates.main([str(source),'--replace','--output-dir',str(output)])
            self.assertEqual(result,2);self.assertFalse(output.exists());self.assertEqual(source.read_bytes(),data)
            self.assertEqual(list(Path(temp).glob('panorama_stage_*')),[])
    def test_cli_end_to_end(self):
        script=Path(__file__).with_name('analyze_duplicates.py')
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'config.xml';data=xml(defs()+group(OLD,NEW)+security(OLD));source.write_bytes(data)
            result=Path(temp)/'result'
            command=[sys.executable,str(script),str(source),'--replace','--output-dir',str(result)]
            done=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertEqual(source.read_bytes(),data)
            with (result/'duplicates.csv').open() as handle:
                self.assertEqual(len(list(csv.reader(handle))),2)
            audit=json.loads((result/'replacement_audit.json').read_text())
            self.assertEqual(audit['summary']['collapsed_members'],1)
            self.assertEqual(audit['output_sha256'],hashlib.sha256((result/'modified.xml').read_bytes()).hexdigest())
            again=subprocess.run(command,capture_output=True,text=True);self.assertEqual(again.returncode,2)
            twice=Path(temp)/'twice'
            done=subprocess.run([sys.executable,str(script),str(result/'modified.xml'),'--replace','--output-dir',str(twice)],capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertEqual((result/'modified.xml').read_bytes(),(twice/'modified.xml').read_bytes())

if __name__=='__main__':unittest.main()
