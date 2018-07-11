#!/usr/bin/python2
import sys
from cvechecker import CVECheck
cveobj=CVECheck()
pobj=dict()
cve=sys.argv[1]
retval,pobj=cveobj.read_store('vulnstore.json',pobj)
if retval == 0:
    print pobj[cve]
