#!/usr/bin/env python2
from cvechecker import CVECheck
import timeit

def myfunc():
    print 'Will now only read'
    cveobj=CVECheck()
    pobj=dict()
    retval,pobj=cveobj.read_store('CVE-2017.json',pobj)
    print len(pobj)
    return pobj

def myfunc2():
    print 'Will now read and write'
    cveobj=CVECheck()
    pobj=dict()
    retval,pobj=cveobj.read_store('CVE-2017.json',pobj)
    print len(pobj)
    cveobj.write_store('test.json',pobj)

print timeit.timeit(myfunc,number=1)
print timeit.timeit(myfunc2,number=1)
