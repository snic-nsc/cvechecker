#!/usr/bin/env python3

from cvechecker import CVECheck
cveobj=CVECheck()
pobj=dict()
retval,pobj=cveobj.read_store('vulnstore.json',pobj)
for cve,vals in pobj.items():
    if not vals.__contains__('muting_reason'):
        vals['muting_reason'] = 'Batch-mute'
    if not vals.__contains__('muting_product'):
        vals['muting_product'] = 'Misc'
    if not vals.__contains__('mitigation'):
        vals['mitigation'] = 'None'
    if vals.__contains__('history'):
        for histitem in vals['history']:
            if not histitem['changelog'].__contains__('rhupdated'):
                histitem['changelog']['rhupdated'] = False
            if not histitem['changelog'].__contains__('nvdaffectedproducts'):
                histitem['changelog']['nvdaffectedproducts'] = False
            if not histitem.__contains__('histitementrydate'):
                histitem['histitementrydate'] = 'Unrecorded'
print("Please don't interrupt before this script completes")
cveobj.write_store('vulnstore.json',pobj)
