#!/usr/bin/python2
import sys
from cvechecker import CVECheck
cveobj=CVECheck()
pobj=dict()
cve=sys.argv[1]
retval,pobj=cveobj.read_store('vulnstore.json',pobj)
if retval == 0:
    if pobj[cve].__contains__('history'):
        histitemcount=len(pobj[cve]['history'])
        print('number of history items: %d'%histitemcount)
    print (pobj[cve])
