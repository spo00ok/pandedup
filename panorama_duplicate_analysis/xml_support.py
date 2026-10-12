"""Strict config parsing and surgical XML member patching; standard library only."""
import xml.etree.ElementTree as ET
from xml.parsers import expat
from xml.sax.saxutils import escape

class NoDTD(ET.TreeBuilder):
    def doctype(self, name, pubid, system):
        raise ValueError('DTD declarations are not allowed')

def parse(data, preserve=False):
    root=ET.fromstring(data,parser=ET.XMLParser(target=NoDTD(insert_comments=preserve,insert_pis=preserve)))
    if root.tag=='config':
        config=root
    elif root.tag=='response' and root.get('status')=='success' and len(root.findall('./result'))==1 and len(root.findall('./result/config'))==1:
        config=root.find('./result/config')
    else:
        raise ValueError('Expected full <config> or successful single-config XML API response')
    for node in config.iter():
        if not isinstance(node.tag,str): continue
        if '}' in node.tag or ':' in node.tag:
            raise ValueError('Namespaced configuration is unsupported')
        singleton=('shared','devices','readonly','address','address-group','region','external-list','device-group','parent-dg','static','dynamic','ip-netmask','ip-range','fqdn','ip-wildcard','source','destination','pre-rulebase','post-rulebase','rulebase','security','rules')
        for tag in singleton:
            if len(node.findall('./'+tag))>1:
                raise ValueError(f'Repeated singleton XML element: {node.tag}/{tag}')
        if node.tag=='entry':
            for tag in ('ip-netmask','ip-range','fqdn','ip-wildcard'):
                for child in node.findall('./'+tag):
                    if len(child): raise ValueError('Address value must be plain text')
    return root,config

def patch_members(data, original_root, edits):
    """Map Expat byte offsets to original ET nodes; never replace arbitrary text."""
    try: data.decode('utf-8-sig')
    except UnicodeDecodeError as exc: raise ValueError('Modification requires UTF-8 XML; analysis supports other XML encodings') from exc
    parser=expat.ParserCreate()
    spans=[]; stack=[]
    def declaration(version,encoding,standalone):
        if encoding and encoding.casefold().replace('-','') not in ('utf8','usascii','ascii'):
            raise ValueError('Modification requires UTF-8 or ASCII XML declaration')
    def start(name,attrs):
        offset=parser.CurrentByteIndex
        # XML start tag scan must respect > inside quoted attributes.
        quote=None; end=offset
        while end<len(data):
            char=data[end]
            if quote:
                if char==quote:quote=None
            elif char in (34,39):quote=char
            elif char==62:break
            end+=1
        record={'start':offset,'inner':end+1,'empty':data[offset:end].rstrip().endswith(b'/')}
        spans.append(record);stack.append(record)
    def end(name):
        record=stack.pop();offset=parser.CurrentByteIndex
        record['close']=record['inner'] if record['empty'] else offset
        record['end']=record['inner'] if record['empty'] else data.index(b'>',offset)+1
    parser.XmlDeclHandler=declaration;parser.StartElementHandler=start;parser.EndElementHandler=end
    parser.Parse(data,True)
    nodes=[n for n in original_root.iter() if isinstance(n.tag,str)]
    if len(nodes)!=len(spans):raise ValueError('XML node/byte-offset mismatch')
    by_id={id(node):span for node,span in zip(nodes,spans)}
    patches=[]
    for node,new in edits:
        span=by_id[id(node)]
        if new is None:patches.append((span['start'],span['end'],b''))
        elif span['empty']:raise ValueError('Cannot replace an empty member')
        else:patches.append((span['inner'],span['close'],escape(new).encode('ascii','xmlcharrefreplace')))
    patches.sort()
    for first,second in zip(patches,patches[1:]):
        if first[1]>second[0]:raise ValueError('Overlapping XML patches')
    chunks=[];cursor=0
    for start,end,value in patches:chunks.extend((data[cursor:start],value));cursor=end
    chunks.append(data[cursor:])
    return b''.join(chunks)
