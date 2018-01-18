#!/usr/bin/env python2
import codecs
import sys
import argparse
from collections import OrderedDict
from hashlib import sha256
import simplejson as json
from numbers import Number
import socket
import time
import datetime
import urllib
import gzip
import os

reload(sys)
sys.setdefaultencoding('utf-8')
socket.setdefaulttimeout(30)

class CVE:
    def __init__(self):
        self.cveid=None
        self.cveurl=None
        self.cvescore=None
        self.affectedpackages=list()
        self.rhproducts=dict()
        self.affectedproducts=dict()
        self.descriptions=list()
        self.details=list()
        self.mitigation=None
        self.nvddescriptions=list()
        self.lastmodifieddate=None
        self.isnew=True

    def update_cve(self,cveid, cveurl,cvescore,affectedpackages,rhproducts,affectedproducts,descriptions,details,mitigation,nvddescriptions,lastmodifieddate):
        pass

class Result:
    def __init__(self):
        self.resultdict=dict()
        self.sentinel=0
        self.scoredefs=OrderedDict()
        self.scoredefs['None']={'high':0.0, 'low':0.0}
        self.scoredefs['Low']={'high':3.9, 'low':0.1}
        self.scoredefs['Medium']={'high':6.9, 'low':4.0}
        self.scoredefs['High']={'high':8.9, 'low':7.0}
        self.scoredefs['Critical']={'high':10.0, 'low':9.0}
        self.scoredefs['Missing']={'high':11.0, 'low':11.0}
    
    def add_result(self, cveid, cveurl, cvescore, affectedpackages, rhproducts, affectedproducts,descriptions,details, mitigation, nvddescriptions, lastmodifieddate):
        if self.resultdict.__contains__(cveid):
            if descriptions != None:
                self.resultdict[cveid]['descriptions']=descriptions
            if details != None:
                self.resultdict[cveid]['details']=details
            if mitigation != None:
                self.resultdict[cveid]['mitigation']=mitigation
            if nvddescriptions != None:
                self.resultdict[cveid]['nvddescriptions']=nvddescriptions
            if cvescore != None:
                if cvescore == 11:
                    if not self.resultdict[cveid].__contains__('score'):
                        self.resultdict[cveid]['score']=11
                else:
                    self.resultdict[cveid]['score']=cvescore
            if lastmodifieddate != None:
                self.resultdict[cveid]['lastmodifieddate']=lastmodifieddate
                if self.resultdict[cveid]['muteddate'] != "":
                    mtdstr=self.resultdict[cveid]['muteddate']
                    mtdobj=datetime.datetime.strptime(mtdstr,'%Y-%m-%d %H:%M')
                    modifdobj=datetime.datetime.strptime(lastmodifieddate,'%Y-%m-%d %H:%M')
                    if modifdobj > mtdobj:
                        self.resultdict[cveid]['muteddate']=''
                        self.resultdict[cveid]['mute']='off'
                                    
            if affectedpackages != None:
                for pkg in affectedpackages:
                    if not self.resultdict[cveid]['affectedpackages'].__contains__(pkg):
                        self.resultdict[cveid]['affectedpackages'].append(pkg)

            if rhproducts != None:
                for newprod,newpkg in rhproducts.iteritems():
                    if not self.resultdict[cveid]['rhproducts'].__contains__(newprod):
                        self.resultdict[cveid]['rhproducts'][newprod]=list()
                        self.resultdict[cveid]['rhproducts'][newprod].append(newpkg)
                    else:
                        if not self.resultdict[cveid]['rhproducts'][newprod].__contains__(newpkg):
                            self.resultdict[cveid]['rhproducts'][newprod].append(newpkg)
                    
            if affectedproducts != None:
                for vendor,proddict in affectedproducts.iteritems():
                    if not self.resultdict[cveid]['affectedproducts'].__contains__(vendor):
                        self.resultdict[cveid]['affectedproducts'][vendor]=proddict
                        continue
                    for prodname,versionlist in proddict.iteritems():
                        if not self.resultdict[cveid]['affectedproducts'][vendor].__contains__(prodname):
                            self.resultdict[cveid]['affectedproducts'][vendor][prodname]=versionlist
                            continue
                        for version in versionlist:
                            if not self.resultdict[cveid]['affectedproducts'][vendor][prodname].__contains__(version):
                                self.resultdict[cveid]['affectedproducts'][vendor][prodname].append(version)
                                continue

        else:
            self.resultdict[cveid]=OrderedDict()
            self.resultdict[cveid]['fresh']=True
            self.resultdict[cveid]['rhproducts']=dict()
            self.resultdict[cveid]['affectedpackages']=list()
            self.resultdict[cveid]['affectedproducts']=dict()
            self.resultdict[cveid]['descriptions']=list()
            self.resultdict[cveid]['nvddescriptions']=list()
            self.resultdict[cveid]['details']=list()
            
            if cvescore != None:
                self.resultdict[cveid]['score']=cvescore
            if cveurl != None:
                self.resultdict[cveid]['url']=cveurl
            self.resultdict[cveid]['mute']='off'
            self.resultdict[cveid]['muteddate']=''
            if affectedpackages != None:
                self.resultdict[cveid]['affectedpackages']=affectedpackages
            if affectedproducts != None:
                self.resultdict[cveid]['affectedproducts']=affectedproducts
            if descriptions != None:
                self.resultdict[cveid]['descriptions']=descriptions
            if nvddescriptions != None:
                self.resultdict[cveid]['nvddescriptions']=nvddescriptions
            if rhproducts != None:
                self.resultdict[cveid]['rhproducts']=rhproducts
            if details != None:
                self.resultdict[cveid]['details']=details
            if lastmodifieddate != None:
                self.resultdict[cveid]['lastmodifieddate']=lastmodifieddate
            return

    def trim_result(self, products=None, packages=None ,scores=None, cves=None, mute='none'):
        newresultdict=dict()
        for key, val in self.resultdict.iteritems():
            if cves != None:
                match=0
                for cve in cves:
                    if key == cve:
                        match=1
                if match == 0:
                    continue
            if scores != None:
                numfails=0
                for score in scores:
                    scorezone=self.scoredefs[score]
                    if val['score'] < scorezone['low'] or val['score'] > scorezone['high']:
                        numfails+=1
                if numfails == len(scores):
                    #this entry fails all specified score requirements
                    continue
            if packages != None:
                found=False
                for package in packages:
                    for affpkg in val['affectedpackages']:
                        if affpkg.startswith(package):
                            found=True
                            break
                    if found:
                        break
                if not found:
                    continue
            if products != None:
                found=False
                for product in products:
                    for vendor,proddict in val['affectedproducts'].iteritems():
                        for prodname, versionlist in proddict.iteritems():
                            if prodname.startswith(product):
                                found=True
                                break
                        if found:
                            break
                    if found:
                        break
                if not found:
                    continue
            newresultdict[key]=val

        #outside the loop
        if mute != 'none':
            for entry in newresultdict:
                newresultdict[entry]['mute']=mute
                self.resultdict[entry]['mute']=mute
                dtobj=datetime.datetime.utcnow()
                dtstr=datetime.datetime.strftime(dtobj,'%Y-%m-%d %H:%M')
                if mute == 'on':
                    newresultdict[entry]['muteddate']=dtstr
                    newresultdict[entry]['fresh']=False
                    self.resultdict[entry]['muteddate']=dtstr
                    self.resultdict[entry]['fresh']=False
                else:
                    newresultdict[entry]['muteddate']=''
                    self.resultdict[entry]['muteddate']=''
                    
            with codecs.open('vulnstore.json','w','utf-8') as outfile:
                json.dump(self.resultdict,outfile)
        self.resultdict=newresultdict

    def print_result(self, mutestate='on'):
        cvelist=list()
        proddict=OrderedDict()
        pkglist=list()
        scorelist=list()
        rhproddict=dict()
        affectedproducts=dict()
        mutecount=0

        for key,val in self.resultdict.iteritems():
            if self.resultdict[key]['mute'] == mutestate:
                mutecount+=1
                continue

            scorelist.append(val['score'])
            if not cvelist.__contains__(key):
                cvelist.append(key)

            for pkg in val['affectedpackages']:
                if not pkglist.__contains__(pkg):
                    pkglist.append(pkg)

            if len(val['rhproducts']) != 0:
                for plt,pkg in val['rhproducts'].iteritems():
                    if not rhproddict.__contains__(plt):
                        rhproddict[plt]=list()
                        rhproddict[plt].append(pkg)
                        continue
                    if not rhproddict[plt].__contains__(pkg):
                        rhproddict[plt].append(pkg)

            for vendor,proddict in val['affectedproducts'].iteritems():
                if not affectedproducts.__contains__(vendor):
                    affectedproducts[vendor]=dict()

                for prod,prodlist in proddict.iteritems():
                    if not affectedproducts[vendor].__contains__(prod):
                        affectedproducts[vendor][prod]=list()

                    for listitem in prodlist:
                        if not affectedproducts[vendor][prod].__contains__(listitem):
                            affectedproducts[vendor][prod].append(listitem)

        if len(self.resultdict)!= 0 and len(self.resultdict)>mutecount:

            print "----------------"
            print "Info from Redhat"
            print "----------------"
            print "Affected Packages"
            print "-----------------"
            for pkg in pkglist:
                print pkg
            print "Redhat Platform info"
            print "--------------------"
            for plat,pkgs in rhproddict.iteritems():
                print "Platform: %s"%plat
                for pkg in pkgs:
                    print pkg
                print ""
            print "----------------"
            print "Info from NVD"
            print "----------------"
            print "Affected Products"
            print "-----------------"
            for vendor,proddict in affectedproducts.iteritems():
                print 'Vendor: %s'%vendor
                for prod,prodlist in proddict.iteritems():
                    print 'Product: %s'%prod
                    print "-------"
                    print ""
                    print 'Affected Versions'
                    print "-----------------"
                    for version in prodlist:
                        print version
                    print ""

            print ""
            print "\nCVE Details"
            print "-----------"
            for cve in cvelist:
                numericscore=self.resultdict[cve]['score']
                for scoredef,rng in self.scoredefs.iteritems():
                    if numericscore > rng['high']:
                        continue
                    textscore=scoredef
                    break
                
                print 'Id:%s Score:%s'%(cve,textscore)
                print "------------------------------------- "
                print 'Redhat'
                for desc in self.resultdict[cve]['descriptions']:
                    print desc
                for detl in self.resultdict[cve]['details']:
                    print detl
                print 'NVD'
                for desc in self.resultdict[cve]['nvddescriptions']:
                    print desc
                print ""

        with open ('listedscores','w') as outfile:
            for score in scorelist:
                outfile.write('%s\n'%score)

        with open ('listedpkgs','w') as outfile:
            for pkg in pkglist:
                outfile.write('%s\n'%pkg)
        with open ('listedcves','w') as outfile:
            for cve in cvelist:
                outfile.write('%s\n'%cve)
            

class CVECheck:
    def __init__(self):
        self.sources=dict()
        self.resObj=Result()
        self.sources['redhat']='https://access.redhat.com/labs/securitydataapi/cve.json'
        self.vulnstore='vulnstore.json'
        self.vulnobj=OrderedDict()
        self.cksumfile='sha256sums'
        self.dontconnect=False
        self.rhproducts=dict()
        self.rhproducts['Red Hat Enterprise Linux 5']='RHEL5'
        self.rhproducts['Red Hat Enterprise Linux 6']='RHEL6'
        self.rhproducts['Red Hat Enterprise Linux 7']='RHEL7'
        self.rhproducts['Red Hat Enterprise Linux 8']='RHEL8'

    def update_from_nvd(self):
        urlobj = urllib.URLopener()
        channelinfo=OrderedDict()
        try:
            with open('nvdchannels.conf','r') as inp:
                lines=inp.readlines()

            for line in lines:
                if line.startswith('#'):
                    continue
                fname=line.split('|')[0]
                fname+='.json'
                metafname=fname+'.meta'
                url=line.split('|')[1]
                metaurl=line.split('|')[2].split('\n')[0]
                zip=fname+'.gz'
                channelinfo[fname]=dict()
                channelinfo[fname]['url']=url
                channelinfo[fname]['metafname']=metafname
                channelinfo[fname]['metaurl']=metaurl
                channelinfo[fname]['zip']=zip
        except:
            print "Catastrophic error with nvdchannels.conf. Check contents for syntax. Refer to nvdchannels.conf.tmpl for help"
            sys.exit(-1)

        cksums=dict()
        try:
            if self.dontconnect:
                raise
            for channel in channelinfo:
                urlobj.retrieve(channelinfo[channel]['metaurl'],channelinfo[channel]['metafname'])
                with open(channelinfo[channel]['metafname'],'r') as inp:
                    lines=inp.readlines()
                cksum=''

                for line in lines:
                    if line.startswith('sha256'):
                        cksum=(line.split(':')[1].split('\r')[0]).lower()
                        break

                if cksum == '':
                    raise
                channelinfo[channel]['sha256sum']=cksum

            #lets compare checksums
            changed=0
            for channel in channelinfo:
                retval,sha256sum=self.compute_checksum(channel)
                if sha256sum != channelinfo[channel]['sha256sum']:
                    print "Update available for %s"%channelinfo[channel]
                    urlobj.retrieve(channelinfo[channel]['url'],channelinfo[channel]['zip'])
                    with gzip.GzipFile(channelinfo[channel]['zip'], 'rb') as f:
                        fcontent = f.read()
                    with open(channel,'wb') as out:
                        out.write(fcontent)
                    os.remove(channelinfo[channel]['zip'])

                #insert into sha256sums if lines not present
                retval=self.check_for_changes(fname=channel)
                if retval != 0:
                    changed=1
                if retval == -1:
                    print "Catastrophic failure. FS error?"
                    sys.exit(-1)
        except:
            if not self.dontconnect:
                print "Could not fetch NVD metadata files; check internet connectivity. Your CVE store could not be updated."
                self.dontconnect=True
            #no metadata files. read the local nvd files
            try:
                for channel in channelinfo:
                    retval=self.check_for_changes(fname=channel)
                    if retval == -1:
                        raise
            except:
                print "Unable to read local nvd files. Execute initnvd.sh"
                raise
            #this is the unupdated case. Local nvd files are available for reading
            return(0,channelinfo)
        #this is the potentially updated case. Local nvd files are available for reading
        if changed == 1:
            return(1,channelinfo)
        else:
            return(0,channelinfo)

    def read_nvd_files(self,channelinfo,retval):
        try:
            with open('vulnstore.json','r') as inp:
                pass
        except:
            print 'No vuln store file found. Initializing from whatever we have.'
            retval=1
        if retval == 0:
            #print 'Nothing has changed from the last invocation. Will read from local store and proceed'
            retval,self.resObj.resultdict=self.read_store(self.vulnstore,self.resObj.resultdict)
            return
        
        exceptioncount=0
        idxcount=0
        basescorex=0
        descx=0
        datex=0
        
        for channel in channelinfo:
            pobj=dict()
            retval,pobj=self.read_store(channel,pobj)
            for cveitem in pobj['CVE_Items']:
                inputs=dict()
                inputs['cveid']=None
                inputs['cveurl']=None
                inputs['cvescore']=None
                inputs['affectedpackages']=None
                inputs['affectedproducts']=dict()
                inputs['rhproducts']=None
                inputs['descriptions']=None
                inputs['details']=None
                inputs['mitigation']=None
                inputs['nvddescriptions']=list()
                inputs['lastmodifieddate']=None
                try:
                    inputs['cveid']=cveitem['cve']['CVE_data_meta']['ID']
                except:
                    idxcount+=1
                try:
                    inputs['cvescore']=cveitem['impact']['baseMetricV3']['cvssV3']['baseScore']
                except:
                    inputs['cvescore']=11 #value for a missing score
                    basescorex+=1
                try:
                    for desc in cveitem['cve']['description']['description_data']:
                        inputs['nvddescriptions'].append(desc['value'])
                except:
                    descx+=1
                try:
                    rdstr=cveitem['lastModifiedDate']
                    dtobj=datetime.datetime.strptime(rdstr,'%Y-%m-%dT%H:%MZ')
                    dtstr=datetime.datetime.strftime(dtobj,'%Y-%m-%d %H:%M')
                    inputs['lastmodifieddate']=dtstr
                except:
                    datex+=1
                try:
                    vendor_list=cveitem['cve']['affects']['vendor']['vendor_data']
                    for vendor in vendor_list:
                        if not inputs['affectedproducts'].__contains__(vendor['vendor_name']):
                            inputs['affectedproducts'][vendor['vendor_name']]=dict()
                        prod_list=vendor['product']['product_data']

                        for prod in prod_list:
                            if not inputs['affectedproducts'][vendor['vendor_name']].__contains__(prod['product_name']):
                                inputs['affectedproducts'][vendor['vendor_name']][prod['product_name']]=list()
                            version_list=prod['version']['version_data']

                            for version in version_list:
                                if not inputs['affectedproducts'][vendor['vendor_name']][prod['product_name']].__contains__(version['version_value']):
                                    inputs['affectedproducts'][vendor['vendor_name']][prod['product_name']].append(version['version_value'])
                    
                    self.resObj.add_result(**inputs)
                except:
                    exceptioncount+=1
                    continue
        #print idxcount,basescorex,descx,datex
        print len(self.resObj.resultdict)
        self.write_store(self.vulnstore,self.resObj.resultdict)
                
    def update_from_redhat(self,url):
        redhatjson='redhat-cve.json'
        try:
            with open('advancedcveinfolist','r') as infile:
                lines=infile.readlines()
            pkgline=''
            for line in lines:
                if line.startswith('packages|'):
                    pkgline=line
                    break
            if pkgline == '':
                raise
            pkglist=pkgline.split('|')[1].split('\n')[0].split(',')
            if pkglist[0] == '':
                raise
        except:
            print 'Please specify packages you wish to query CVEs for, in a file called advancedcveinfolist, containing a line in this format'
            print 'packages|pkg1,pkg2,pkg3...'
            sys.exit(-1)

        filelist=list()
        for pkg in pkglist:
            url=self.sources['redhat']
            url+='?package=%s'%pkg
            if self.dontconnect:
                break
            try:
                cveintobj=json.load(urllib.urlopen(url),object_pairs_hook=OrderedDict)
                fn=pkg+'.json'
                filelist.append(fn)
                self.write_store(fn,cveintobj)
            except:
                print 'cannot update CVEs for redhat packages; check internet connectivity.'
                self.dontconnect=True
        return(filelist)

    def read_redhat_files(self,redhatjsonfilelist):
        initstore=0
        toupdate=list()
        for redhatjson in redhatjsonfilelist:
            retval=self.check_for_changes(fname=redhatjson)
            if retval != 0:
                initstore=1
                toupdate.append(redhatjson)
        retval,self.resObj.resultdict=self.read_store(self.vulnstore,self.resObj.resultdict)
        if retval == -1:
            initstore=1

        if initstore == 1:
            for redhatjson in toupdate:
                rjobj=OrderedDict()
                retval,rjobj=self.read_store(redhatjson,rjobj)
                if retval != 0:
                    sys.exit(-1)
                for rj in rjobj:
                    inputs=dict()
                    inputs['cveid']=None
                    inputs['cveurl']=None
                    inputs['cvescore']=None
                    inputs['affectedpackages']=list()
                    inputs['affectedproducts']=None
                    inputs['rhproducts']=None
                    inputs['descriptions']=list()
                    inputs['details']=None
                    inputs['mitigation']=None
                    inputs['nvddescriptions']=None
                    inputs['lastmodifieddate']=None
                    try:
                        inputs['cveid']=rj['CVE']
                        inputs['cveurl']=rj['resource_url']
                        inputs['affectedpackages']=rj['affected_packages']
                        inputs['cvescore']=rj['cvss3_score']
                    except:
                        moveon=1

                    if inputs['cvescore'] == None:
                        inputs['cvescore']=11 #value for missing score
                    if not self.dontconnect:
                        try:
                            print 'pulling down %s'%(inputs['cveurl'])
                            cveobj=json.load(urllib.urlopen(inputs['cveurl']))
                        except:
                            print 'Failure to fetch CVE details. All data fields may not be available'

                        #RedHat CVE files are very inconsistent with fields.
                        try:
                            inputs['details']=cveobj['details']
                        except:
                            pass
                        try:
                            inputs['descriptions'].append(cveobj['bugzilla']['description'])
                        except:
                            inputs['descriptions'] = None
                        try:
                            intputs['mitigation']=cveobj['mitigation']
                        except:
                            pass

                        apdict=OrderedDict()
                        for pstate in cveobj['affected_release']:
                            if not type(pstate) == dict:
                                continue
                            if not pstate.__contains__('package'):
                                continue
                            try:
                                apdict[self.rhproducts[pstate['product_name']]]=pstate['package']
                            except:
                                apdict[pstate['product_name']]=pstate['package']
                        inputs['rhproducts']=apdict

                    self.resObj.add_result(**inputs)

            try:
                self.write_store(self.vulnstore,self.resObj.resultdict)
            except:
                print 'Fatal error writing output into local vuln store file'
                sys.exit(-1)
            return
        else: # nothing to do here. resultdict has been initialized from vuln object directly, and there are no more changes.
            return
    
    def compute_checksum(self,fname):
        try:
            sha256sum=''
            with open(fname,'rb') as infile:
                sha256sum=sha256(infile.read()).hexdigest()
            return(0,sha256sum)
        except:
            return(-1,sha256sum)
            

    def check_for_changes(self,url=None,fname=None):
        if url != None:
            try:
                urlobj = urllib.URLopener()
                urlobj.retrieve(url,fname)
            except:
                return(-1)

        cksums=OrderedDict()
        try:
            with open(self.cksumfile,'r') as infile:
                lines=infile.readlines()
            for line in lines:
                cksums[line.split(' ')[1].split('\n')[0]]=line.split(' ')[0]
            changed=0
            retval,sha256sum=self.compute_checksum(fname)
            if retval == -1:
                return(-1)

            if cksums[fname] != sha256sum:
                print "checksum list has been updated for file %s."%(fname)
                cksums[fname]=sha256sum
                changed=1
            if changed == 0:
                return(0)
            else:
                with open('sha256sums','w') as outfile:
                    for file in cksums:
                        outfile.write("%s %s\n"%(cksums[file],file))
                return(1)
        except:
            print "Could not look up old checksum. Will add"
            cksums[fname]=sha256sum
            with open('sha256sums','w') as outfile:
                for file in cksums:
                    outfile.write("%s %s\n"%(cksums[file],file))
                return(1)

    def update_store(self):
        #first RedHat
        jsonfilelist=self.update_from_redhat(self.sources['redhat'])
        self.read_redhat_files(jsonfilelist)
        #now NVD
        retval,channelinfo=self.update_from_nvd()
        self.read_nvd_files(channelinfo,retval)

    def read_store(self,jsonfile,jsonobj):
        try:
            with codecs.open(jsonfile,'r','utf-8') as infile:
                jsonobj=json.load(infile)
        except:
            return(-1,jsonobj)
        return(0,jsonobj)

    def write_store(self,jsonfile, jsonobj):
        with codecs.open(jsonfile,'w','utf-8') as outfile:
            json.dump(jsonobj,outfile)

def main():

    aparser=argparse.ArgumentParser(description='A tool to fetch and update a local vulnerability store against select sources of vulnerability information. It can be queried for specific CVEs, by severity or product name, or a combination. Entries can be marked as "seen" to allow one to "mute" alerts for onal words into the corpus.')
    aparser.add_argument("-c", "--cve", type=str, default='none',help='output information about specified CVE or comma-separated list of CVEs. Cannot be combined with any other filter/option.')
    aparser.add_argument("-s", "--severity", type=str,default='none',help='filter results by severity level. Valid levels are "None", "Low", "Medium", "High", and "Critical". Needs to be used with --product.') #lookup by severity level
    aparser.add_argument("-p", "--product", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by product, e.g. http_server
    aparser.add_argument("-m", "--mute", type=str, default='none',help='set mute on or off, to silence/unsilence reporting. Must be used in combination with one of --product or --cve options') #mark results as seen or unseen
    aparser.add_argument("-u", "--update", type=str, nargs='?',default='none',help='update the vulnerability store. Should be run regularly, preferably from a cron.')
    aparser.add_argument("-d", "--disp-mute", type=str, nargs='?',default='none',help='display muted entries. --cve or --product filters may be used in conjuction with -d.')
    aparser.add_argument("-e", "--examples", type=str, nargs='?',default='none',help='display usage examples.')

    args=aparser.parse_args()
    cve=args.cve
    severity=args.severity
    product=args.product
    mute=args.mute
    disp_mute=args.disp_mute
    update=args.update
    examples=args.examples

    argsdict=dict()
    argsdict['scores']=None
    argsdict['products']=None
    argsdict['cves']=None
    resobj=Result()
    cvcobj=CVECheck()

    if examples != 'none':
        print './cvechecker.py: Simply displays the help.'
        print './cvechecker.py -p http_server,tivoli,slurm,postgres,general_parallel_file_system,irods,torque_resource_manager,struts,java: Display CVEs against these products'
        print './cvechecker.py -p postgres,http_server --severity=High,Critical,Missing: List vulnerabilities if any, for specified packages, and filter on CVE score'
        print './cvechecker.py -pkg postgres --severity Medium --mute on: Muting alerts for all matching results'
        print './cvechecker.py -pkg chromium --severity Medium --mute off: Unmuting alerts for matching results'
        print './cvechecker.py -d: Display CVEs that have been muted, and packages that it affects.'
        sys.exit(0)

    if severity != 'none':
        scores=severity.split(',')
        for score in scores:
            if score != 'None' and score != 'Low' and score != 'High' and score != 'Medium' and score != 'Critical' and score != 'Missing':
                print 'Invalid severity level!'
                sys.exit(-1)
        if product == 'none':
            print 'This option requires you to specify at least one product with the --product option'
            sys.exit(-1)
        cve='none'
        argsdict['scores']=scores


    if product != 'none':
        argsdict['products']=product.split(',')
        cve='none'

    if mute != 'none':
        if mute != 'on' and mute != 'off':
            print 'Value for mute flag can only be "off" or "on"'
            sys.exit(-1)
        if product == 'none' and cve == 'none':
            print 'Mute flag requires the use of the --product or the --cve option. If both are specified, --product is ignored.'
            sys.exit(-1)
        if product != 'none' and cve != 'none':
            product='none'
        argsdict['mute']=mute

    if update != 'none':
        cvcobj.update_store()
        sys.exit(0)

    if cve != 'none':
        argsdict['cves']=cve.split(',')
        argsdict['scores']=None
        argsdict['products']=None

    if len(sys.argv) == 1:
        aparser.print_help()

    if mute != 'none' or product != 'none' or cve != 'none' or disp_mute != 'none':
        retval,cvcobj.resObj.resultdict=cvcobj.read_store(cvcobj.vulnstore,cvcobj.resObj.resultdict)
        if retval == -1:
            print 'Trouble initializing from local vuln store. Aborting.'
            sys.exit(-1)

        cvcobj.resObj.trim_result(**argsdict)
        if mute != 'none':
            sys.exit(0)

        if disp_mute != 'none':
            cvcobj.resObj.print_result(mutestate='off')
        else:
            cvcobj.resObj.print_result()
if __name__ == "__main__":
    main()
