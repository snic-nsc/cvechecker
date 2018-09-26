#!/usr/bin/env python3
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
import urllib.request, urllib.parse, urllib.error
import gzip
import os
import difflib

socket.setdefaulttimeout(30)

class CVE:
    def __init__(self):
        self.cveid = None
        self.cveurl = None
        self.cvescore = None
        self.affectedproducts = dict()
        self.descriptions = list()
        self.details = list()
        self.mitigation = None
        self.nvddescriptions = list()
        self.lastmodifieddate = None
        self.isnew = True

    def update_cve(self,cveid, cveurl,cvescore,affectedproducts,details,mitigation,nvddescriptions,lastmodifieddate):
        pass

class Result:
    def __init__(self):
        self.resultdict = dict()
        self.sentinel = 0
        self.scoredefs = OrderedDict()
        self.scoredefs['None'] = {'high':0.0, 'low':0.0}
        self.scoredefs['Low'] = {'high':3.9, 'low':0.1}
        self.scoredefs['Medium'] = {'high':6.9, 'low':4.0}
        self.scoredefs['High'] = {'high':8.9, 'low':7.0}
        self.scoredefs['Critical'] = {'high':10.0, 'low':9.0}
        self.scoredefs['Missing'] = {'high':11.0, 'low':11.0}
    
    def add_result(self, cveid, cveurl, bugzilla_desc, bugzilla_url, cvescore, affectedproducts,details, redhat_info,mitigation, nvddescriptions, nvdrefs, lastmodifieddate):
        if self.resultdict.__contains__(cveid):
            if lastmodifieddate != None:
                lmtdobj = datetime.datetime.strptime(lastmodifieddate,'%Y-%m-%d %H:%M')
                if self.resultdict[cveid].__contains__('lastmodifieddate') and self.resultdict[cveid]['lastmodifieddate'] != None: # we might have an update
                    storedlmtdobj = datetime.datetime.strptime(self.resultdict[cveid]['lastmodifieddate'],'%Y-%m-%d %H:%M')
                    if storedlmtdobj < lmtdobj: #we indeed have an update
                        self.resultdict[cveid]['muteddate'] = ''
                        self.resultdict[cveid]['mute'] = 'off'
                        self.resultdict[cveid]['status'] = 'Update'

                        #now to identify and note what's changed

                        changelog = dict()
                        histitem = dict()
                        histitem['lastmodifieddate'] = self.resultdict[cveid]['lastmodifieddate']
                        self.resultdict[cveid]['lastmodifieddate']=lastmodifieddate
                        changelog['score'] = False
                        changelog['nvddescriptions'] = False
                        changelog['nvdrefs'] = False
                        changelog['other'] = False
                        if cvescore != 11:
                            if self.resultdict[cveid]['score'] != cvescore:
                                changelog['score'] = True
                                if self.resultdict[cveid]['score'] == 11:
                                    histitem['score'] = 'Missing'
                                else:
                                    histitem['score'] = self.resultdict[cveid]['score']

                        if nvddescriptions != None:
                            if len(nvddescriptions) != 0:
                                if len(self.resultdict[cveid]['nvddescriptions']) == 0:
                                    changelog['nvddescriptions'] = True
                                    histitem['nvddescriptions'] = list()
                                else:
                                    for description in nvddescriptions:
                                        found = False
                                        for sdesc in self.resultdict[cveid]['nvddescriptions']:
                                            if description == sdesc:
                                                found = True
                                                break
                                        if found == False:
                                            changelog['nvddescriptions'] = True
                                            histitem['nvddescriptions'] = self.resultdict[cveid]['nvddescriptions']
                                            break

                        if nvdrefs != None:
                            if len(nvdrefs) != 0:
                                if len(self.resultdict[cveid]['nvdrefs']) == 0:
                                    changelog['nvdrefs'] = True
                                    histitem['nvdrefs']= list()
                                else:
                                    for refitem in nvdrefs:
                                        found = False
                                        for srefitem in self.resultdict[cveid]['nvdrefs']:
                                            if refitem == srefitem:
                                                found = True
                                                break
                                        if found == False:
                                            changelog['nvdrefs'] = True
                                            histitem['nvdrefs'] = self.resultdict[cveid]['nvdrefs']
                                            break
                        if changelog['score'] == False and changelog['nvddescriptions'] == False and changelog['nvdrefs'] == False:
                            changelog['other'] = True
                        if changelog['score'] == False and changelog['nvddescriptions'] == False and changelog['nvdrefs'] == True:
                            self.resultdict[cveid]['status'] = 'R-Update'
                        histitem['changelog']=changelog
                        if not self.resultdict[cveid].__contains__('history'):
                            self.resultdict[cveid]['history'] = list()
                        self.resultdict[cveid]['history'].append(histitem)
                        
                else:
                    self.resultdict[cveid]['lastmodifieddate'] = lastmodifieddate

            if redhat_info != None:
                self.resultdict[cveid]['redhat_info'] = redhat_info
            if bugzilla_desc != None:
                self.resultdict[cveid]['bugzilla_desc'] = bugzilla_desc
            if bugzilla_url != None:
                self.resultdict[cveid]['bugzilla_url'] = bugzilla_url
            if details != None:
                self.resultdict[cveid]['details'] = details
            if mitigation != None:
                self.resultdict[cveid]['mitigation'] = mitigation
            if nvddescriptions != None:
                self.resultdict[cveid]['nvddescriptions'] = nvddescriptions
            if nvdrefs != None:
                self.resultdict[cveid]['nvdrefs'] = nvdrefs
            if cvescore != None:
                if cvescore == 11:
                    if not self.resultdict[cveid].__contains__('score'):
                        self.resultdict[cveid]['score'] = 11
                else:
                    self.resultdict[cveid]['score'] = cvescore
                                    
            if affectedproducts != None:
                for vendor,proddict in affectedproducts.items():
                    if not self.resultdict[cveid]['affectedproducts'].__contains__(vendor):
                        self.resultdict[cveid]['affectedproducts'][vendor] = proddict
                        continue
                    for prodname,versionlist in proddict.items():
                        if not self.resultdict[cveid]['affectedproducts'][vendor].__contains__(prodname):
                            self.resultdict[cveid]['affectedproducts'][vendor][prodname] = versionlist
                            continue
                        for version in versionlist:
                            if not self.resultdict[cveid]['affectedproducts'][vendor][prodname].__contains__(version):
                                self.resultdict[cveid]['affectedproducts'][vendor][prodname].append(version)
                                continue

        else:
            self.resultdict[cveid] = OrderedDict()
            dtobj = datetime.datetime.utcnow()
            dtstr = datetime.datetime.strftime(dtobj,'%Y-%m-%d %H:%M')
            self.resultdict[cveid]['insertiondate'] = dtstr
            self.resultdict[cveid]['status'] = 'Fresh'
            self.resultdict[cveid]['affectedproducts'] = dict()
            self.resultdict[cveid]['nvddescriptions'] = list()
            self.resultdict[cveid]['nvdrefs'] = list()
            self.resultdict[cveid]['redhat_info'] = dict()
            self.resultdict[cveid]['bugzilla_url'] = None
            self.resultdict[cveid]['bugzilla_desc'] = None
            self.resultdict[cveid]['details'] = None
        
            if redhat_info != None:
                self.resultdict[cveid]['redhat_info'] = redhat_info

            if bugzilla_desc != None:
                self.resultdict[cveid]['bugzilla_desc'] = bugzilla_desc
            if bugzilla_url != None:
                self.resultdict[cveid]['bugzilla_url'] = bugzilla_url
            
            if cvescore != None:
                self.resultdict[cveid]['score'] = cvescore
            if cveurl != None:
                self.resultdict[cveid]['url'] = cveurl
            self.resultdict[cveid]['mute'] = 'off'
            self.resultdict[cveid]['muteddate'] = ''
            if affectedproducts != None:
                self.resultdict[cveid]['affectedproducts'] = affectedproducts
            if nvddescriptions != None:
                self.resultdict[cveid]['nvddescriptions'] = nvddescriptions
            if nvdrefs != None:
                self.resultdict[cveid]['nvdrefs'] = nvdrefs
            if details != None:
                self.resultdict[cveid]['details'] = details
            if lastmodifieddate != None:
                self.resultdict[cveid]['lastmodifieddate'] = lastmodifieddate
            return

    def trim_result(self, products=None, keywords=None, scores=None, cves=None, afterdate=None, excludes=None, mute='none'):
        newresultdict = dict()
        if cves != None:
            for cve in cves:
                if self.resultdict.__contains__(cve):
                    newresultdict[cve]= self.resultdict[cve]
        else:
            for key, val in self.resultdict.items():
                if scores != None:
                    numfails = 0
                    for score in scores:
                        scorezone=self.scoredefs[score]
                        if val['score'] < scorezone['low'] or val['score'] > scorezone['high']:
                            numfails += 1
                    if numfails == len(scores):
                        #this entry fails all specified score requirements
                        continue
                found = False
                if keywords != None:
                    for keyword in keywords:
                        keyword += ' '
                        if len(val['nvddescriptions']) > 0:
                            for desc in val['nvddescriptions']:
                                if desc.find(keyword) != -1:
                                    excluded=False
                                    if excludes != None:
                                            for vendor,proddict in val['affectedproducts'].items():
                                                for prodname in proddict:
                                                    if excludes.__contains__(prodname):
                                                        excluded=True
                                                        break
                                                if excluded == True:
                                                    break
                                            if excluded == True:
                                                break
                                    found = True
                                    val['matchedon'] = keyword
                                    val['matchtype'] = 'keyword'
                                    break
                        if found:
                            break
                    if not found:
                        # if a product-based search is also requested, we need to check for a product match before eliminating the result
                        if products == None:
                            continue

                if products != None and found == False:
                    for product in products:
                        for vendor,proddict in val['affectedproducts'].items():
                            for prodname, versionlist in proddict.items():
                                if prodname.startswith(product):
                                    excluded=False
                                    if excludes != None:
                                        if excludes.__contains__(prodname):
                                            excluded=True
                                            break
                                    found = True
                                    val['matchedon'] = product
                                    val['matchtype'] = 'product'
                                    break
                            if excluded == True:
                                continue
                            if found:
                                break
                        if excluded == True:
                            continue
                        if found:
                            break
                        #plugin point for rh-product check
                        if val['details'] != None:
                            if val['redhat_info'].__contains__('PackageState'):
                                if len(val['redhat_info']['PackageState']) >0:
                                    for match in val['redhat_info']['PackageState']:
                                        if match.__contains__('PackageName'):
                                            if match['PackageName'].startswith(product):
                                                #print("%s starts with %s"%(match['PackageName'],product))
                                                excluded = False
                                                if excludes != None:
                                                    for excl in excludes:
                                                        if match['PackageName'] == excl:
                                                            excluded = True
                                                            break
                                                if excluded == True:
                                                    break
                                                found = True
                                                val['matchedon'] = match['PackageName']
                                                val['matchtype'] = 'product'
                                                break
                            if found:
                                break
                    if not found:
                        continue
                if afterdate != None:
                    #first check for last-modified date. If absent, look for redhat affectedrelease; if that too isn't available, drop result.
                    if val.__contains__('lastmodifieddate'):
                        dtobj = datetime.datetime.strptime(val['lastmodifieddate'],'%Y-%m-%d %H:%M')
                        if not dtobj > afterdate:
                            continue
                    else:
                        if val.__contains__('redhat_info') and val['redhat_info'].__contains__('AffectedRelease') and len(val['redhat_info']['AffectedRelease']) != 0:
                            found=False
                            for item in val['redhat_info']['AffectedRelease']:
                                dtobj = datetime.datetime.strptime(item['ReleaseDate'],'%Y-%m-%dT%H:%M:%S')
                                if dtobj > afterdate:
                                    found=True
                            if found == False:
                                continue
                        else:
                            #unable to determine if it's reasonably recent, so dropping, as we've been requested only to provide what is confirmed to be after a certain date
                            continue
                newresultdict[key] = val

        #outside the loop
        
        if mute != 'none':
            for entry in newresultdict:
                newresultdict[entry]['mute'] = mute
                self.resultdict[entry]['mute'] = mute
                dtobj = datetime.datetime.utcnow()
                dtstr = datetime.datetime.strftime(dtobj,'%Y-%m-%d %H:%M')
                if mute == 'on':
                    newresultdict[entry]['muteddate'] = dtstr
                    newresultdict[entry]['status'] = 'Seen'
                    self.resultdict[entry]['muteddate'] = dtstr
                    self.resultdict[entry]['status'] = 'Seen'
                else:
                    newresultdict[entry]['muteddate'] = ''
                    self.resultdict[entry]['muteddate'] = ''
                    
            with codecs.open('vulnstore.json','w','utf-8') as outfile:
                json.dump(self.resultdict,outfile)
        self.resultdict = newresultdict

    def print_result(self, readconfig, conffile, mutestate='on'):
        cvelist = list()
        proddict = OrderedDict()
        pkglist = list()
        scorelist = list()
        affectedproducts = dict()
        mutecount = 0

        for key,val in self.resultdict.items():
            if self.resultdict[key]['mute'] == mutestate:
                mutecount += 1
                continue
            if self.resultdict[key]['bugzilla_desc'] != None:
                hdr = self.resultdict[key]['bugzilla_desc'].split('\n')[1]
            else:
                hdr = key
            if mutestate == 'off':
                print('Printing muted entry')
                print('Record insertion date: %s'%val['insertiondate'])
                print('Record muted date: %s'%val['muteddate'])
            if readconfig:
                print('Config file used: %s'%conffile)
            print("---BEGIN REPORT---")
            print(hdr)
            hdrlen = len(hdr)
            for i in range(0,hdrlen):
                sys.stdout.write('=')
            print("\nhttps://nvd.nist.gov/vuln/detail/"+key+"\n")
            if val.__contains__('matchedon'):
                print("Match-type: %s\nMatched on: %s"%(val['matchtype'],val['matchedon']))
            print("Status: %s"%val['status'])
            numericscore = self.resultdict[key]['score']
            for scoredef,rng in self.scoredefs.items():
                if numericscore > rng['high']:
                    continue
                textscore = scoredef
                break
            print("Score %s (%s)"%(numericscore,textscore))
            if val.__contains__('insertiondate'):
                print("First seen date: %s"%val['insertiondate'])
            if val.__contains__('lastmodifieddate'):
                print("Last Modification date: %s"%val['lastmodifieddate'])
            if val['status'] == 'Update' or val['status'] == 'R-Update':
                print("\nChangelog")
                print("----------")
                print("")
                lastitem=len(val['history'])-1
                changelog=val['history'][lastitem]['changelog']
                if changelog['score'] == True:
                    print("Present score: %s. Previous score: %s\n"%(val['score'],val['history'][lastitem]['score']))
                if changelog['nvdrefs'] == True:
                    print("References section updated. Diff follows\n")
                    diff=difflib.unified_diff(val['history'][lastitem]['nvdrefs'],val['nvdrefs'],lineterm='')
                    print('\n'.join(diff))
                    print('\n')
                if changelog['nvddescriptions'] == True:
                    print("NVD's description of the vulnerability has been modified. Diff follows\n")
                    diff=difflib.unified_diff(val['history'][lastitem]['nvddescriptions'],val['nvddescriptions'],lineterm='')
                    print('\n'.join(diff))
                    print('\n')
                if changelog['other'] == True:
                    print("Information other than what is tracked by cvechecker, has been modified, e.g addition of CWE.")
                    print("Check for updates here: https://nvd.nist.gov/vuln/detail/%s#VulnChangeHistorySection"%(key))
            print("")
            print("Info from Redhat")
            print("----------------")
            rhinfoavailable = False
            if self.resultdict[key]['details'] != None:
                rhinfoavailable = True
                print(self.resultdict[key]['details'])
                if self.resultdict[key]['redhat_info']['score'] != 11:
                    if val['score'] != 11 and val['score'] != self.resultdict[key]['redhat_info']['score']:
                        print('Redhat cvemap.xml notes a CVSSV3 score of %s for this CVE, but NVD notes %s. NVD is to be considered a more reliable source'%(self.resultdict[key]['redhat_info']['score'],val['score']))
                    else:
                        print('Redhat cvemap.xml notes a CVSSV3 score of %s for this CVE.'%(self.resultdict[key]['redhat_info']['score']))

                rhinfoavailable = False
                if self.resultdict[key]['redhat_info'].__contains__('PackageState'):
                    rhinfoavailable = True

                if  rhinfoavailable == True:
                    print("")
                    print("Redhat Platform info")
                    print("--------------------")
                    if len(self.resultdict[key]['redhat_info']['PackageState']) >0:
                        print("")
                        print("Package State")
                        print("-------------")
                        for match in self.resultdict[key]['redhat_info']['PackageState']:
                            for test in ['ProductName','PackageName','FixState']:
                                if match.__contains__(test):
                                    print("%s: %s"%(test,match[test]))
                            print("\n")
                if self.resultdict[key]['redhat_info'].__contains__('AffectedRelease'):
                    if len(self.resultdict[key]['redhat_info']['AffectedRelease']) >0:
                        print("")
                        print("Affected Package Info")
                        print("---------------------")
                        for match in self.resultdict[key]['redhat_info']['AffectedRelease']:
                            for test in ['ProductName','Package','ReleaseDate','advisory_url']:
                                if match.__contains__(test):
                                    print("%s: %s"%(test,match[test]))
                            print("\n")
                if self.resultdict[key].__contains__('mitigation') and self.resultdict[key]['mitigation'] != None:
                        print("Mitigation")
                        print("----------")
                        print("%s"%(self.resultdict[key]['mitigation']))

            else:
                print("Nil")
            print("")
            print("Info from NVD")
            print("-------------")
            print("")
            if len(self.resultdict[key]['nvddescriptions']) != 0:
                for desc in self.resultdict[key]['nvddescriptions']:
                    print(desc)
            print("")
            print("Affected Products")
            print("-----------------")
            for vendor,proddict in val['affectedproducts'].items():
                print('\nVendor: %s'%vendor)
                for prod,prodlist in proddict.items():
                    print('\n\tProduct: %s'%prod)
                    sys.stdout.write('\tAffected Versions: ')
                    afcount = len(prodlist)
                    afctr = 0
                    for version in prodlist:
                        if afctr < afcount-1:
                            sys.stdout.write("%s, "%version)
                        else:
                            sys.stdout.write("%s\n"%version)
                        afctr += 1

            print("\nReferences")
            print("----------")
            print("")
            for url in val['nvdrefs']:
                print("%s    "%(url))
            print("---END REPORT---")

class CVECheck:
    def __init__(self,dontconnect=False):
        self.sources = dict()
        self.resObj = Result()
        self.sources['redhat'] = 'https://www.redhat.com/security/data/metrics/cvemap.xml'
        self.vulnstore = 'vulnstore.json'
        self.conffile = 'cvechecker.conf'
        self.readconfig = False
        self.vulnobj = OrderedDict()
        self.cksumfile = 'sha256sums'
        self.dontconnect = dontconnect

    def update_from_nvd(self):
        channelinfo = OrderedDict()
        try:
            with open('nvdchannels.conf','r') as inp:
                lines = inp.readlines()

            for line in lines:
                if line.startswith('#'):
                    continue
                fname = line.split('|')[0]
                fname += '.json'
                metafname = fname+'.meta'
                url = line.split('|')[1]
                metaurl = line.split('|')[2].split('\n')[0]
                zip = fname+'.gz'
                channelinfo[fname] = dict()
                channelinfo[fname]['url'] = url
                channelinfo[fname]['metafname'] = metafname
                channelinfo[fname]['metaurl'] = metaurl
                channelinfo[fname]['zip'] = zip
        except:
            print("Catastrophic error with nvdchannels.conf. Check contents for syntax. Refer to nvdchannels.conf.tmpl for help")
            sys.exit(-1)

        cksums = dict()
        try:
            if not self.dontconnect:
                for channel in channelinfo:
                    urllib.request.urlretrieve(channelinfo[channel]['metaurl'],channelinfo[channel]['metafname'])
                    with open(channelinfo[channel]['metafname'],'r') as inp:
                        lines = inp.readlines()
                    cksum = ''

                    for line in lines:
                        if line.startswith('sha256'):
                            cksum = (line.split(':')[1].split('\n')[0]).lower()
                            break

                    if cksum == '':
                        raise
                    channelinfo[channel]['sha256sum'] = cksum

            #lets compare checksums
            changed = False
            for channel in channelinfo:
                if not self.dontconnect:
                    retval,sha256sum = self.compute_checksum(channel)
                    if sha256sum != channelinfo[channel]['sha256sum']:
                        print("Update available for %s"%channelinfo[channel])
                        urllib.request.urlretrieve(channelinfo[channel]['url'],channelinfo[channel]['zip'])
                        f=gzip.GzipFile(channelinfo[channel]['zip'], 'rb')
                        fcontent = f.read()
                        f.close()
                        with open(channel,'wb') as out:
                            out.write(fcontent)
                        os.remove(channelinfo[channel]['zip'])

                #insert into sha256sums if lines not present
                retval = self.check_for_changes(fname=channel)
                if retval != 0:
                    changed = True
                    print("Updated file %s successfully."%channel)
                if retval == -1:
                    sys.exit(-1)
            if changed == False:
                print("No update available from NVD.")
        except:
            if not self.dontconnect:
                print("Could not fetch NVD metadata files; check internet connectivity. Your CVE store could not be updated.")
                self.dontconnect = True
            #no metadata files. read the local nvd files
            try:
                for channel in channelinfo:
                    retval = self.check_for_changes(fname=channel)
                    if retval == -1:
                        raise
            except:
                print("NVD json files not found. Execute cvechecker.py -u and retry")
                raise
            #this is the unupdated case. Local nvd files are available for reading
            return(False,channelinfo)
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
            print('No vuln store file found. Initializing from whatever we have.')
            retval = True
        if retval == False:
            print('Nothing has changed from the last invocation.')
            return
        
        exceptioncount = 0
        idxcount = 0
        basescorex = 0
        descx = 0
        datex = 0
        refexp = 0
        
        for channel in channelinfo:
            pobj = dict()
            retval,pobj = self.read_store(channel,pobj)
            for cveitem in pobj['CVE_Items']:
                inputs = dict()
                inputs['cveid'] = None
                inputs['cveurl'] = None
                inputs['bugzilla_desc'] = None
                inputs['bugzilla_url'] = None
                inputs['cvescore'] = None
                inputs['affectedproducts'] = dict()
                inputs['details'] = None
                inputs['redhat_info'] = None
                inputs['mitigation'] = None
                inputs['nvddescriptions'] = list()
                inputs['nvdrefs'] = list()
                inputs['lastmodifieddate'] = None
                try:
                    inputs['cveid'] = cveitem['cve']['CVE_data_meta']['ID']
                except:
                    idxcount += 1
                try:
                    inputs['cvescore'] = cveitem['impact']['baseMetricV3']['cvssV3']['baseScore']
                except:
                    inputs['cvescore'] = 11 #value for a missing score
                    basescorex += 1
                try:
                    for desc in cveitem['cve']['description']['description_data']:
                        inputs['nvddescriptions'].append(desc['value'])
                except:
                    descx += 1
                try:
                    for refitem in cveitem['cve']['references']['reference_data']:
                        for junk,url in refitem.items():
                            if junk == "tags":
                                continue
                            inputs['nvdrefs'].append(url)
                except:
                    refexp += 1
                try:
                    rdstr = cveitem['lastModifiedDate']
                    dtobj = datetime.datetime.strptime(rdstr,'%Y-%m-%dT%H:%MZ')
                    dtstr = datetime.datetime.strftime(dtobj,'%Y-%m-%d %H:%M')
                    inputs['lastmodifieddate'] = dtstr
                except:
                    datex += 1
                try:
                    vendor_list = cveitem['cve']['affects']['vendor']['vendor_data']
                    for vendor in vendor_list:
                        if not inputs['affectedproducts'].__contains__(vendor['vendor_name']):
                            inputs['affectedproducts'][vendor['vendor_name']] = dict()
                        prod_list = vendor['product']['product_data']

                        for prod in prod_list:
                            if not inputs['affectedproducts'][vendor['vendor_name']].__contains__(prod['product_name']):
                                inputs['affectedproducts'][vendor['vendor_name']][prod['product_name']] = list()
                            version_list = prod['version']['version_data']

                            for version in version_list:
                                if not inputs['affectedproducts'][vendor['vendor_name']][prod['product_name']].__contains__(version['version_value']):
                                    inputs['affectedproducts'][vendor['vendor_name']][prod['product_name']].append(version['version_value'])
                    
                    self.resObj.add_result(**inputs)
                except:
                    exceptioncount += 1
                    continue
        #print idxcount,basescorex,descx,datex
        #print 'datex is %s'%(str(datex))
        #print 'descx is %s'%(str(descx))
        print(len(self.resObj.resultdict))
        self.write_store(self.vulnstore,self.resObj.resultdict)
                
    def update_from_redhat(self,url):
            url = self.sources['redhat']
            if self.dontconnect:
                return(False,'cvemap.xml')
            try:
                urllib.request.urlretrieve(url,'cvemap.xml')
                tree = ET.parse('cvemap.xml')
                root = tree.getroot()
                if root.tag != 'cvemap':
                    raise
            except:
                print('cannot update CVEs for redhat packages; check internet connectivity.')
                return(False,None)
            retval = self.check_for_changes(fname='cvemap.xml')
            if retval == 0:
                print("No update available from Redhat.")
                return(False,'cvemap.xml')
            if retval == -1:
                print("Catastrophic failure. FS error?")
                sys.exit(-1)
            if retval == 1:
                print("Redhat CVE xml updated successfully.")
                return(True,'cvemap.xml')

    def assign_if_present(self,vulnfieldname,inputfieldname,vulnobj,inputobj,operation=None):
        if vulnobj.__contains__(vulnfieldname):
            if operation == 'append':
                if not inputobj.__contains__(inputfieldname):
                    inputobj[inputfieldname] = list()
                for val in vulnobj[vulnfieldname]:
                    inputobj[inputfieldname].append(val)
            else:
                inputobj[inputfieldname] = vulnobj[vulnfieldname]
        else:
            if operation == 'append':
                inputobj[inputfieldname] = list()
            else:
                inputobj[inputfieldname] = None
            
    def read_redhat_files(self,cvexml):

        try:
            tree = ET.parse('cvemap.xml')
            root = tree.getroot()
        except:
            print("Could not parse cvemap.xml.");
            sys.exit(-1)
    
        vulndict = OrderedDict()
        for child in root:
            cveid = child.attrib['name']
            vulndict[cveid] = OrderedDict()
            for field in child:
                if field.tag not in ['UpstreamFix','Mitigation','PublicDate','CVSS3','Bugzilla','ThreatSeverity','Details','PackageState','AffectedRelease']:
                    continue
                if field.tag == 'CVSS3':
                    if field.attrib['status'] !='verified':
                        continue
                    if field[0].tag == 'CVSS3BaseScore':
                        vulndict[cveid]['score'] = field[0].text
                        continue
                if field.tag == 'Bugzilla':
                    vulndict[cveid]['bugzilla_url'] = field.attrib['url']
                if field.tag == 'Details':
                    vulndict[cveid]['source'] = field.attrib['source']
                if field.tag == 'PackageState':
                    if not vulndict[cveid].__contains__('PackageState'):
                        vulndict[cveid]['PackageState'] = list()
                    psdict = dict()
                    psdict['cpe'] = field.attrib['cpe']
                    for f in field:
                        psdict[f.tag] = f.text
                    vulndict[cveid]['PackageState'].append(psdict)
                    continue
                if field.tag == 'AffectedRelease':
                    if not vulndict[cveid].__contains__('AffectedRelease'):
                        vulndict[cveid]['AffectedRelease'] = list()
                    af = dict()
                    af['cpe'] = field.attrib['cpe']
                    for f in field:
                        af[f.tag] = f.text
                        if f.tag == 'Advisory':
                            af['advisory_url'] = f.attrib['url']
                    vulndict[cveid]['AffectedRelease'].append(af)
                    continue
                vulndict[cveid][field.tag] = field.text
            if not vulndict[cveid].__contains__('score'):
                vulndict[cveid]['score'] = 11

        for cveid, cveobj in vulndict.items():
            inputs = dict()
            inputs['cveid'] = cveid
            inputs['cveurl'] = None
            inputs['affectedproducts'] = None
            self.assign_if_present('Bugzilla','bugzilla_desc',cveobj,inputs)
            self.assign_if_present('bugzilla_url','bugzilla_url',cveobj,inputs)
            self.assign_if_present('Details','details',cveobj,inputs)
            inputs['redhat_info'] = dict()
            inputs['redhat_info']['PackageState'] = list() 
            inputs['redhat_info']['AffectedRelease'] = list()
            inputs['redhat_info']['score'] = float(cveobj['score'])
            inputs['cvescore'] = 11 # to not mess around with NVD scores.
            if cveobj.__contains__('AffectedRelease'):
                inputs['redhat_info']['AffectedRelease'] = cveobj['AffectedRelease']
            if cveobj.__contains__('PackageState'):
                inputs['redhat_info']['PackageState'] = cveobj['PackageState']
            inputs['mitigation'] = None
            self.assign_if_present('Mitigation','mitigation',cveobj,inputs)
            inputs['nvddescriptions'] = None
            inputs['nvdrefs'] = None
            inputs['lastmodifieddate'] = None
            self.resObj.add_result(**inputs)

        try:
            self.write_store(self.vulnstore,self.resObj.resultdict)
        except:
            print('Fatal error writing output into local vuln store file')
            sys.exit(-1)
        return
    
    def compute_checksum(self,fname):
        try:
            sha256sum = ''
            with open(fname,'rb') as infile:
                sha256sum = sha256(infile.read()).hexdigest()
            return(0,sha256sum)
        except:
            return(-1,sha256sum)
            
    def get_checksum(self,fname):
        cksums = OrderedDict()
        with open(self.cksumfile,'r') as infile:
            lines = infile.readlines()
        for line in lines:
            cksums[line.split(' ')[1].split('\n')[0]] = line.split(' ')[0]
        
        if cksums.__contains__(fname):
            return (0,cksums[fname])
        return (-1,None)

    def check_for_changes(self,url=None,fname=None):
        if url != None:
            try:
                urllib.request.urlretrieve(url,fname)
            except:
                return(-1)

        cksums = OrderedDict()
        try:
            with open(self.cksumfile,'r') as infile:
                lines = infile.readlines()
            for line in lines:
                cksums[line.split(' ')[1].split('\n')[0]] = line.split(' ')[0]
            changed = False
            retval,sha256sum = self.compute_checksum(fname)
            if retval == -1:
                return(-1)

            if cksums[fname] != sha256sum:
                print("checksum list has been updated for file %s."%(fname))
                cksums[fname] = sha256sum
                changed = True
            if changed == False:
                return(0)
            else:
                with open('sha256sums','w') as outfile:
                    for file in cksums:
                        outfile.write("%s %s\n"%(cksums[file],file))
                return(1)
        except:
            print("Could not look up old checksum for file %s. Will add"%(fname))
            cksums[fname]= sha256sum
            with open('sha256sums','w') as outfile:
                for file in cksums:
                    outfile.write("%s %s\n"%(cksums[file],file))
                return(1)

    def update_store(self):
        #first read in the vulnstore, so we don't accidentally forget what we've seen or muted
        retval,self.resObj.resultdict = self.read_store(self.vulnstore,self.resObj.resultdict)
        #next we check for updates from RedHat
        retval,cvexml = self.update_from_redhat(self.sources['redhat'])
        if retval == True:
            self.read_redhat_files(cvexml)
        else:
            if self.dontconnect == True:
                self.read_redhat_files(cvexml)
        #lastly, updates from NVD
        retval,channelinfo = self.update_from_nvd()
        if retval == True:
            self.read_nvd_files(channelinfo,retval)
        else:
            if self.dontconnect == True:
                self.read_nvd_files(channelinfo,True)

    def read_store(self,jsonfile,jsonobj):
        try:
            with codecs.open(jsonfile,'r','utf-8') as infile:
                jsonobj = json.load(infile)
        except:
            return(-1,jsonobj)
        return(0,jsonobj)

    def write_store(self,jsonfile, jsonobj):
        with codecs.open(jsonfile,'w','utf-8') as outfile:
            json.dump(jsonobj,outfile)

def main():

    aparser = argparse.ArgumentParser(description='A tool to fetch and update a local vulnerability store against select sources of vulnerability information. It can be queried for specific CVEs, by severity or product name, or a combination. Entries can be marked as "seen" to allow one to "mute" alerts.')
    aparser.add_argument("-a", "--after-date", type=str, nargs='?',default='none',help='only list matches whose last modified date is after the given date. Date format YYYY-MM-DD.')
    aparser.add_argument("-c", "--cve", type=str, default='none',help='output information about specified CVE or comma-separated list of CVEs. Cannot be combined with any other filter/option.')
    aparser.add_argument("-d", "--disp-mute", type=str, nargs='?',default='none',help='display muted entries. --cve or --product filters may be used in conjuction with -d.')
    aparser.add_argument("-e", "--examples", type=str, nargs='?',default='none',help='display usage examples.')
    aparser.add_argument("-k", "--keyword", type=str, default='none',help='filter results by specified keyword/comma-separated list of keywords in CVE description text from NVD. Can be combined with -p, to get a union set.') #lookup by keyword e.g. Intel
    aparser.add_argument("-m", "--mute", type=str, default='none',help='set mute on or off, to silence/unsilence reporting. Must be used in combination with one of --product or --cve options') #mark results as seen or unseen
    aparser.add_argument("-n", "--no-connection", type=str, nargs='?',default='none',help='do not connect to external servers (NVD, Redhat), to fetch updated CVE information (useful while debugging).')
    aparser.add_argument("-p", "--product", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by product, e.g. http_server
    aparser.add_argument("-r", "--read-config", type=str, nargs='?',default='none',help='read package and keyword filter values from the configuration file. Additional filters may be provided on the command-line. Optional argument: configuration file to be read; defaults to cvechecker.conf')
    aparser.add_argument("-s", "--severity", type=str,default='none',help='filter results by severity level. Valid levels are "None", "Low", "Medium", "High", and "Critical". Needs to be used with --product, or --after-date.') #lookup by severity level
    aparser.add_argument("-u", "--update", type=str, nargs='?',default='none',help='update the vulnerability store. Should be run regularly, preferably from a cron.')
    aparser.add_argument("-x", "--exclude", type=str,default='none',help='suppress reporting for these packages; useful to avoid false-positive matches;  ex matching xenmobile for xen filter.') #exclude matches

    args = aparser.parse_args()
    cve = args.cve
    noconnect = args.no_connection
    severity = args.severity
    products = args.product
    mute = args.mute
    disp_mute = args.disp_mute
    update = args.update
    examples = args.examples
    exclude = args.exclude
    keywords = args.keyword
    afterdate = args.after_date
    readconfig = args.read_config

    argsdict = dict()
    argsdict['scores'] = None
    argsdict['products'] = None
    argsdict['cves'] = None
    argsdict['afterdate'] = None
    argsdict['keywords'] = None
    argsdict['excludes'] = None
    resobj = Result()
    if noconnect != 'none':
        cveobj = CVECheck(True)
    else:
        cveobj = CVECheck()

    if examples != 'none':
        print('./cvechecker.py: Simply displays the help.')
        print('./cvechecker.py -p http_server,tivoli,slurm,postgres,general_parallel_file_system,irods,torque_resource_manager,struts,java: Display CVEs against these products')
        print('./cvechecker.py -p postgres,http_server --severity=High,Critical,Missing: List vulnerabilities if any, for specified products, and filter on CVE score')
        print('./cvechecker.py -p postgres --severity Medium --mute on: Muting alerts for all matching results')
        print('./cvechecker.py -p chromium --severity Medium --mute off: Unmuting alerts for matching results')
        print('./cvechecker.py -d: Display CVEs that have been muted, and packages that it affects.')
        print('./cvechecker.py -k Intel,InfiniBand,AMD: Display CVEs with descriptions containing these keywords. Case-sensitive, to avoid too many false positives.')
        sys.exit(0
)
    if afterdate != 'none':
        try:
            dtcheck = datetime.datetime.strptime(afterdate,'%Y-%m-%d')
        except:
            print('Invalid date or incorrect format. Use the YYYY-MM-DD convention')
            sys.exit(-1)
        if cve != 'none':
            print('Cannot specify -c and -a flags simultaneously')
            sys.exit(-1)
        argsdict['afterdate']=dtcheck

    if severity != 'none':
        scores = severity.split(',')
        for score in scores:
            if score != 'None' and score != 'Low' and score != 'High' and score != 'Medium' and score != 'Critical' and score != 'Missing':
                print('Invalid severity level!')
                sys.exit(-1)
        if products == 'none' and afterdate == 'none' and keywords == 'none':
            print('This option requires you to specify at least one product/keyword, or specify the --after-date option')
            sys.exit(-1)
        cve = 'none'
        argsdict['scores'] = scores

    if products != 'none':
        prods = products.split(',')
        prods.sort()
        argsdict['products'] = list()
        for prod in prods:
            if not argsdict['products'].__contains__(prod):
                argsdict['products'].append(prod)
        if cve != 'none':
            print('Cannot specify -c and -p flags simultaneously')
            sys.exit(-1)
        cve = 'none'

    if keywords != 'none':
        kwds = keywords.split(',')
        argsdict['keywords'] = list()
        for kwd in kwds:
            if not argsdict['keywords'].__contains__(kwd):
                argsdict['keywords'].append(kwd)
        if cve != 'none':
            print('Cannot specify -c and -k flags simultaneously')
            sys.exit(-1)
        cve = 'none'

    if exclude != 'none':
        excls = exclude.split(',')
        argsdict['excludes'] = list()
        for excl in excls:
            if not argsdict['excludes'].__contains__(excl):
                argsdict['excludes'].append(excl)
        cve = 'none'
        if cve != 'none':
            print('Cannot specify -c and -x flags simultaneously')
            sys.exit(-1)

    if readconfig != 'none':
        cveobj.readconfig = True
        if readconfig != None:
            cveobj.conffile = readconfig
        try:
            f = open(cveobj.conffile,'r')
            lines = f.readlines()
            f.close()
            for line in lines:
                table=dict.fromkeys(map(ord, '"\''),None)
                line=line.translate(table)
                if line.startswith('packages='):
                    pkgs=line.split('\n')[0].split('=')[1].split(',')
                    if len(pkgs) != 0 and pkgs != ['']:
                        cve = 'none'
                        products=''
                        if argsdict['products'] != None:
                            for pkg in argsdict['products']:
                                pkgs.append(pkg)
                        pkgs.sort()
                        argsdict['products']=list()
                        for pkg in pkgs:
                            if not argsdict['products'].__contains__(pkg):
                                argsdict['products'].append(pkg)
                if line.startswith('keywords='):
                    kwds=line.split('\n')[0].split('=')[1].split(',')
                    if len(kwds) != 0 and kwds != ['']:
                        keywords = ''
                        cve = 'none'
                        if argsdict['keywords'] != None:
                            for kwd in argsdict['keywords']:
                                kwds.append(kwd)
                        kwds.sort()
                        argsdict['keywords']=list()
                        for kwd in kwds:
                            if not argsdict['keywords'].__contains__(kwd):
                                argsdict['keywords'].append(kwd)
                if line.startswith('excludes='):
                    excls=line.split('\n')[0].split('=')[1].split(',')
                    if len(excls) != 0 and excls != ['']:
                        excludes = ''
                        cve = 'none'
                        if argsdict['excludes'] != None:
                            for excl in argsdict['excludes']:
                                excls.append(excl)
                        excls.sort()
                        argsdict['excludes']=list()
                        for excl in excls:
                            if not argsdict['excludes'].__contains__(excl):
                                argsdict['excludes'].append(excl)
        except:
            print('Config file %s not present or contents unreadable'%cveobj.conffile)
            sys.exit(-1)
      
    if mute != 'none':
        if mute != 'on' and mute != 'off':
            print('Value for mute flag can only be "off" or "on"')
            sys.exit(-1)
        if products == 'none' and cve == 'none' and keywords == 'none':
            print('Mute flag requires the use of the --product, --keyword, or the --cve filter. If --cve is specified with other filters, the other filters are.')
            sys.exit(-1)
        if products != 'none' and cve != 'none':
            products = 'none'
        if keywords != 'none' and cve != 'none':
            keywords = 'none'
        argsdict['mute'] = mute

    if update != 'none':
        cveobj.update_store()
        sys.exit(0)

    if cve != 'none':
        argsdict['cves'] = cve.split(',')
        argsdict['scores'] = None
        argsdict['products'] = None
        argsdict['keywords'] = None
        argsdict['afterdate'] = None
        argsdict['excludes'] = None

    if len(sys.argv) == 1:
        aparser.print_help()

    if mute != 'none' or products != 'none' or cve != 'none' or disp_mute != 'none' or keywords != 'none' or afterdate != 'none':
        retval,cveobj.resObj.resultdict = cveobj.read_store(cveobj.vulnstore,cveobj.resObj.resultdict)
        if retval == -1:
            print('Trouble initializing from local vuln store. Aborting.')
            sys.exit(-1)
        
        cveobj.resObj.trim_result(**argsdict)
        if mute != 'none':
            sys.exit(0)

        if disp_mute != 'none':
            cveobj.resObj.print_result(cveobj.readconfig,cveobj.conffile,mutestate='off')
        else:
            cveobj.resObj.print_result(cveobj.readconfig,cveobj.conffile)
if __name__ == "__main__":
    main()
