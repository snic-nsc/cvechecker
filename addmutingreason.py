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
cveobj.write_store('vulnstore.json',pobj)
