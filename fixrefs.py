#!/usr/bin/env python3

from cvechecker import CVECheck
cveobj=CVECheck()
pobj=dict()
retval,pobj=cveobj.read_store('vulnstore.json',pobj)
for cve,vals in pobj.items():
    ctr=-1
    poplist=list()
    if vals.__contains__('nvdrefs'):
        for i in vals['nvdrefs']:
            ctr+=1
            if type(i) == list:
                poplist.append(ctr)
        poplist.reverse()
        for i in poplist:
            popped=pobj[cve]['nvdrefs'].pop(i)
            print(popped)
    if vals.__contains__('history'):
        for histitem in vals['history']:
            if histitem.__contains__('nvdrefs'):
                ctr=-1
                poplist=list()
                for i in histitem['nvdrefs']:
                    ctr+=1
                    if type(i) == list:
                        poplist.append(ctr)
                poplist.reverse()
                for i in poplist:
                    popped=histitem['nvdrefs'].pop(i)
                    print(popped)
cveobj.write_store('vulnstore.json',pobj)
            
        
