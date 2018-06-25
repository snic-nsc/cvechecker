#!/usr/bin/env python2
# Original author: pchengi@nsc.liu.se

import codecs
import sys
import argparse
from collections import OrderedDict
from hashlib import sha256
import simplejson as json
from numbers import Number
import xml.etree.ElementTree as ET
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
        self.affectedproducts=dict()
        self.descriptions=list()
        self.details=list()
        self.mitigation=None
        self.nvddescriptions=list()
        self.lastmodifieddate=None
        self.isnew=True

    def update_cve(self,cveid, cveurl,cvescore,affectedproducts,details,mitigation,nvddescriptions,lastmodifieddate):
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
    
    def add_result(self, cveid, cveurl, bugzilla_desc, bugzilla_url, cvescore, affectedproducts,details, redhat_info,mitigation, nvddescriptions, nvdrefs, lastmodifieddate):
        if self.resultdict.__contains__(cveid):
            if redhat_info != None:
                self.resultdict[cveid]['redhat_info']=redhat_info
            if bugzilla_desc != None:
                self.resultdict[cveid]['bugzilla_desc']=bugzilla_desc
            if bugzilla_url != None:
                self.resultdict[cveid]['bugzilla_url']=bugzilla_url
            if details != None:
                self.resultdict[cveid]['details']=details
            if mitigation != None:
                self.resultdict[cveid]['mitigation']=mitigation
            if nvddescriptions != None:
                self.resultdict[cveid]['nvddescriptions']=nvddescriptions
            if nvdrefs != None:
                self.resultdict[cveid]['nvdrefs']=nvdrefs
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
            dtobj=datetime.datetime.utcnow()
            dtstr=datetime.datetime.strftime(dtobj,'%Y-%m-%d %H:%M')
            self.resultdict[cveid]['insertiondate']=dtstr
            self.resultdict[cveid]['fresh']=True
            self.resultdict[cveid]['affectedproducts']=dict()
            self.resultdict[cveid]['nvddescriptions']=list()
            self.resultdict[cveid]['nvdrefs']=list()
            self.resultdict[cveid]['redhat_info']=dict()
            self.resultdict[cveid]['bugzilla_url']=None
            self.resultdict[cveid]['bugzilla_desc']=None
            self.resultdict[cveid]['details']=None
        
            if redhat_info != None:
                self.resultdict[cveid]['redhat_info']=redhat_info

            if bugzilla_desc != None:
                self.resultdict[cveid]['bugzilla_desc']=bugzilla_desc
            if bugzilla_url != None:
                self.resultdict[cveid]['bugzilla_url']=bugzilla_url
            
            if cvescore != None:
                self.resultdict[cveid]['score']=cvescore
            if cveurl != None:
                self.resultdict[cveid]['url']=cveurl
            self.resultdict[cveid]['mute']='off'
            self.resultdict[cveid]['muteddate']=''
            if affectedproducts != None:
                self.resultdict[cveid]['affectedproducts']=affectedproducts
            if nvddescriptions != None:
                self.resultdict[cveid]['nvddescriptions']=nvddescriptions
            if nvdrefs != None:
                self.resultdict[cveid]['nvdrefs']=nvdrefs
            if details != None:
                self.resultdict[cveid]['details']=details
            if lastmodifieddate != None:
                self.resultdict[cveid]['lastmodifieddate']=lastmodifieddate
            return

    def trim_result(self, products=None, keywords=None, scores=None, cves=None, mute='none'):
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
            found=False
            if keywords != None:
                for keyword in keywords:
                    keyword+=' '
                    if len(val['nvddescriptions']) > 0:
                        for desc in val['nvddescriptions']:
                            if desc.find(keyword) != -1:
                                found=True
                                break
                    if found:
                        break
                if not found:
                    # if a product-based search is also requested, we need to check for a product match before eliminating the result
                    if products == None:
                        continue

            if products != None and found == False:
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
        affectedproducts=dict()
        mutecount=0

        for key,val in self.resultdict.iteritems():
            if self.resultdict[key]['mute'] == mutestate:
                mutecount+=1
                continue
            if self.resultdict[key]['bugzilla_desc'] != None:
                hdr=self.resultdict[key]['bugzilla_desc'].split('\n')[1]
            else:
                hdr=key
            print "---BEGIN REPORT---"
            print hdr
            hdrlen=len(hdr)
            for i in range(0,hdrlen):
                sys.stdout.write('=')
            print "\nhttps://nvd.nist.gov/vuln/detail/"+key+"\n"
            if val['fresh'] == True:
                print "Status: Fresh    "
            else:
                print "Status: Update    "
            numericscore=self.resultdict[key]['score']
            for scoredef,rng in self.scoredefs.iteritems():
                if numericscore > rng['high']:
                    continue
                textscore=scoredef
                break
            print "Score %s (%s)"%(numericscore,textscore)
            #print "----------------"
            print ""
            print "Info from Redhat"
            print "----------------"
            rhinfoavailable=False

            if self.resultdict[key]['details'] != None:
                rhinfoavailable=True
                print self.resultdict[key]['details']

            if self.resultdict[key]['redhat_info'].__contains__('PackageState'):
                rhinfoavailable=True

            if  rhinfoavailable==True:
                print ""
                print "Redhat Platform info"
                print "--------------------"
                print ""
                print "Package State"
                print "-------------"
                if len(self.resultdict[key]['redhat_info']['PackageState']) >0:
                    for match in self.resultdict[key]['redhat_info']['PackageState']:
                        for test in ['ProductName','PackageName','FixState']:
                            if match.__contains__(test):
                                print "%s: %s"%(test,match[test])
                        print "\n"
            if self.resultdict[key]['redhat_info'].__contains__('AffectedRelease'):
                if len(self.resultdict[key]['redhat_info']['AffectedRelease']) >0:
                    print ""
                    print "Affected Package Info"
                    print "---------------------"
                    for match in self.resultdict[key]['redhat_info']['AffectedRelease']:
                        for test in ['ProductName','Package','advisory_url']:
                            if match.__contains__(test):
                                print "%s: %s"%(test,match[test])
                        print "\n"

            if rhinfoavailable == False:
                print "Nil"
            print ""
            print "Info from NVD"
            print "-------------"
            print ""
            if len(self.resultdict[key]['nvddescriptions']) != 0:
                for desc in self.resultdict[key]['nvddescriptions']:
                    print desc
            print ""
            print "Affected Products"
            print "-----------------"
            for vendor,proddict in val['affectedproducts'].iteritems():
                print '\nVendor: %s'%vendor
                for prod,prodlist in proddict.iteritems():
                    print '\n\tProduct: %s'%prod
                    sys.stdout.write('\tAffected Versions: ')
                    afcount=len(prodlist)
                    afctr=0
                    for version in prodlist:
                        if afctr < afcount-1:
                            sys.stdout.write("%s, "%version)
                        else:
                            sys.stdout.write("%s\n"%version)
                        afctr+=1

            print "\nReferences"
            print "----------"
            print ""
            for url in val['nvdrefs']:
                print "%s    "%(url)
            print "---END REPORT---"

class CVECheck:
    def __init__(self):
        self.sources=dict()
        self.resObj=Result()
        self.sources['redhat']='https://www.redhat.com/security/data/metrics/cvemap.xml'
        self.vulnstore='vulnstore.json'
        self.vulnobj=OrderedDict()
        self.cksumfile='sha256sums'
        self.dontconnect=False

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
            changed=False
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
                    changed=True
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
        if changed == True:
            return(True,channelinfo)
        else:
            return(False,channelinfo)

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
        refexp=0
        
        for channel in channelinfo:
            pobj=dict()
            retval,pobj=self.read_store(channel,pobj)
            for cveitem in pobj['CVE_Items']:
                inputs=dict()
                inputs['cveid']=None
                inputs['cveurl']=None
                inputs['bugzilla_desc']=None
                inputs['bugzilla_url']=None
                inputs['cvescore']=None
                inputs['affectedproducts']=dict()
                inputs['details']=None
                inputs['redhat_info']=None
                inputs['mitigation']=None
                inputs['nvddescriptions']=list()
                inputs['nvdrefs']=list()
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
                    for refitem in cveitem['cve']['references']['reference_data']:
                        for junk,url in refitem.iteritems():
                            inputs['nvdrefs'].append(url)
                except:
                    refexp+=1
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
            url=self.sources['redhat']
            if self.dontconnect:
                return(False,None)
            try:
                urlobj = urllib.URLopener()
                urlobj.retrieve(url,'cvemap.xml')
                tree=ET.parse('cvemap.xml')
                root=tree.getroot()
                if root.tag != 'cvemap':
                    raise
            except:
                print 'cannot update CVEs for redhat packages; check internet connectivity.'
                return(False,None)
            retval=self.check_for_changes(fname='cvemap.xml')
            if retval == 0:
                print "No update available from Redhat"
                return(False,'cvemap.xml')
            if retval == -1:
                print "Catastrophic failure. FS error?"
                sys.exit(-1)
            if retval == 1:
                print "Redhat CVE xml updated successfully."
                return(True,'cvemap.xml')

    def assign_if_present(self,vulnfieldname,inputfieldname,vulnobj,inputobj,operation=None):
        if vulnobj.__contains__(vulnfieldname):
            if operation == 'append':
                if not inputobj.__contains__(inputfieldname):
                    inputobj[inputfieldname]=list()
                for val in vulnobj[vulnfieldname]:
                    inputobj[inputfieldname].append(val)
            else:
                inputobj[inputfieldname]=vulnobj[vulnfieldname]
        else:
            if operation == 'append':
                inputobj[inputfieldname]=list()
            else:
                inputobj[inputfieldname]=None
            
    def read_redhat_files(self,cvexml):
        retval,self.resObj.resultdict=self.read_store(self.vulnstore,self.resObj.resultdict)

        try:
            tree=ET.parse('cvemap.xml')
            root=tree.getroot()
        except:
            print "Could not parse cvemap.xml.";
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
                    vulndict[cveid]['bugzilla_url']=field.attrib['url']
                if field.tag == 'Details':
                    vulndict[cveid]['source']=field.attrib['source']
                if field.tag == 'PackageState':
                    if not vulndict[cveid].__contains__('PackageState'):
                        vulndict[cveid]['PackageState']=list()
                    psdict=dict()
                    psdict['cpe']=field.attrib['cpe']
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
            if not vulndict[cveid].__contains__('score'):
                vulndict[cveid]['score']=11

        for cveid, cveobj in vulndict.iteritems():
            inputs=dict()
            inputs['cveid']=cveid
            inputs['cveurl']=None
            inputs['affectedproducts']=None
            self.assign_if_present('Bugzilla','bugzilla_desc',cveobj,inputs)
            self.assign_if_present('bugzilla_url','bugzilla_url',cveobj,inputs)
            self.assign_if_present('score','cvescore',cveobj,inputs)
            self.assign_if_present('Details','details',cveobj,inputs)
            inputs['redhat_info']=dict()
            inputs['redhat_info']['PackageState']=list() 
            inputs['redhat_info']['AffectedRelease']=list()
            if cveobj.__contains__('AffectedRelease'):
                inputs['redhat_info']['AffectedRelease']=cveobj['AffectedRelease']
            if cveobj.__contains__('PackageState'):
                inputs['redhat_info']['PackageState']=cveobj['PackageState']
            inputs['mitigation']=None
            self.assign_if_present('Mitigation','mitigation',cveobj,inputs)
            inputs['nvddescriptions']=None
            inputs['nvdrefs']=None
            inputs['lastmodifieddate']=None
            self.resObj.add_result(**inputs)

        try:
            self.write_store(self.vulnstore,self.resObj.resultdict)
        except:
            print 'Fatal error writing output into local vuln store file'
            sys.exit(-1)
        return
    
    def compute_checksum(self,fname):
        try:
            sha256sum=''
            with open(fname,'rb') as infile:
                sha256sum=sha256(infile.read()).hexdigest()
            return(0,sha256sum)
        except:
            return(-1,sha256sum)
            
    def get_checksum(self,fname):
        cksums=OrderedDict()
        with open(self.cksumfile,'r') as infile:
            lines=infile.readlines()
        for line in lines:
            cksums[line.split(' ')[1].split('\n')[0]]=line.split(' ')[0]
        
        if cksums.__contains__(fname):
            return (0,cksums[fname])
        return (-1,None)

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
            changed=False
            retval,sha256sum=self.compute_checksum(fname)
            if retval == -1:
                return(-1)

            if cksums[fname] != sha256sum:
                print "checksum list has been updated for file %s."%(fname)
                cksums[fname]=sha256sum
                changed=True
            if changed == False:
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
        retval,cvexml=self.update_from_redhat(self.sources['redhat'])
        if retval == True:
            self.read_redhat_files(cvexml)
        #now NVD
        retval,channelinfo=self.update_from_nvd()
        if retval == True:
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
    aparser.add_argument("-k", "--keyword", type=str, default='none',help='filter results by specified keyword/comma-separated list of keywords in CVE description text from NVD. Can be combined with -p, to get a union set.') #lookup by keyword e.g. Intel
    aparser.add_argument("-m", "--mute", type=str, default='none',help='set mute on or off, to silence/unsilence reporting. Must be used in combination with one of --product or --cve options') #mark results as seen or unseen
    aparser.add_argument("-u", "--update", type=str, nargs='?',default='none',help='update the vulnerability store. Should be run regularly, preferably from a cron.')
    aparser.add_argument("-d", "--disp-mute", type=str, nargs='?',default='none',help='display muted entries. --cve or --product filters may be used in conjuction with -d.')
    aparser.add_argument("-e", "--examples", type=str, nargs='?',default='none',help='display usage examples.')

    args=aparser.parse_args()
    cve=args.cve
    severity=args.severity
    products=args.product
    mute=args.mute
    disp_mute=args.disp_mute
    update=args.update
    examples=args.examples
    keywords=args.keyword

    argsdict=dict()
    argsdict['scores']=None
    argsdict['products']=None
    argsdict['cves']=None
    resobj=Result()
    cvcobj=CVECheck()

    if examples != 'none':
        print './cvechecker.py: Simply displays the help.'
        print './cvechecker.py -p http_server,tivoli,slurm,postgres,general_parallel_file_system,irods,torque_resource_manager,struts,java: Display CVEs against these products'
        print './cvechecker.py -p postgres,http_server --severity=High,Critical,Missing: List vulnerabilities if any, for specified products, and filter on CVE score'
        print './cvechecker.py -p postgres --severity Medium --mute on: Muting alerts for all matching results'
        print './cvechecker.py -p chromium --severity Medium --mute off: Unmuting alerts for matching results'
        print './cvechecker.py -d: Display CVEs that have been muted, and packages that it affects.'
        print './cvechecker.py -k Intel,InfiniBand,AMD: Display CVEs with descriptions containing these keywords. Case-sensitive, to avoid too many false positives.'
        sys.exit(0)

    if severity != 'none':
        scores=severity.split(',')
        for score in scores:
            if score != 'None' and score != 'Low' and score != 'High' and score != 'Medium' and score != 'Critical' and score != 'Missing':
                print 'Invalid severity level!'
                sys.exit(-1)
        if products == 'none':
            print 'This option requires you to specify at least one product with the --product option'
            sys.exit(-1)
        cve='none'
        argsdict['scores']=scores


    if products != 'none':
        argsdict['products']=products.split(',')
        cve='none'

    if keywords != 'none':
        argsdict['keywords']=keywords.split(',')
        cve='none'

    if mute != 'none':
        if mute != 'on' and mute != 'off':
            print 'Value for mute flag can only be "off" or "on"'
            sys.exit(-1)
        if products == 'none' and cve == 'none' and keywords == 'none':
            print 'Mute flag requires the use of the --product, --keyword, or the --cve filter. If --cve is specified with other filters, the other filters are.'
            sys.exit(-1)
        if products != 'none' and cve != 'none':
            products='none'
        if keywords != 'none' and cve != 'none':
            keywords='none'
        argsdict['mute']=mute

    if update != 'none':
        cvcobj.update_store()
        sys.exit(0)

    if cve != 'none':
        argsdict['cves']=cve.split(',')
        argsdict['scores']=None
        argsdict['products']=None
        argsdict['keywords']=None

    if len(sys.argv) == 1:
        aparser.print_help()

    if mute != 'none' or products != 'none' or cve != 'none' or disp_mute != 'none' or keywords != 'none':
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
