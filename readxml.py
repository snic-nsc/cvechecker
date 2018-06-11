#!/usr/bin/env python
import xml.etree.ElementTree as ET
import simplejson as json
import sys
import pprint
pp = pprint.PrettyPrinter(indent=4)
from collections import OrderedDict
try:
    tree=ET.parse('cvemap.xml')
    root=tree.getroot()
except:
    print "Could not parse xml. Fuck off";
    sys.exit(-1)
    
vulndict=OrderedDict()
for child in root:
    cveid=child.attrib['name']
    vulndict[cveid]=OrderedDict()
    for field in child:
        if field.tag not in ['UpstreamFix','Mitigation','PublicDate','CVSS3','Bugzilla','ThreatSeverity','Details','PackageState','AffectedRelease']:
            continue
        if field.tag == 'CVSS3':
            if field.attrib['status'] !='verified':
                continue
            if field[0].tag == 'CVSS3BaseScore':
                vulndict[cveid]['score']=field[0].text
                continue
        if field.tag == 'Bugzilla':
            vulndict[cveid]['bugzilla-url']=field.attrib['url']
        if field.tag == 'Details':
            vulndict[cveid]['source']=field.attrib['source']
        if field.tag == 'PackageState':
            if not vulndict[cveid].__contains__('PackageState'):
                vulndict[cveid]['PackageState']=list()
            psdict=dict()
            for f in field:
                psdict[f.tag]=f.text
            vulndict[cveid]['PackageState'].append(psdict)
            continue
        if field.tag == 'AffectedRelease':
            if not vulndict[cveid].__contains__('AffectedRelease'):
                vulndict[cveid]['AffectedRelease']=list()
            af=dict()
            af['cpe']=field.attrib['cpe']
            for f in field:
                af[f.tag]=f.text
                if f.tag == 'Advisory':
                    af['advisory_url']=f.attrib['url']
            vulndict[cveid]['AffectedRelease'].append(af)
            continue
        vulndict[cveid][field.tag]=field.text

pp.pprint(vulndict)
