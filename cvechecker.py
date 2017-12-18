#!/usr/bin/env python2
import codecs
import xml.etree.ElementTree as ET
import sys,argparse
from collections import OrderedDict
from hashlib import sha256
import simplejson as json
from numbers import Number
import socket
import urllib,urllib2
import gzip,os

reload(sys)
sys.setdefaultencoding('utf-8')
socket.setdefaulttimeout(30)

class Result:
	def __init__(self):
		self.resultdict=dict()
	
	def addResult(self, cveid, cveurl, cvescore, affectedpackages, rhproducts, affectedproducts,descriptions,details, mitigation, nvddescriptions):
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
				self.resultdict[cveid]['score']=cvescore
			
			if affectedpackages != None:			 
				for pkg in affectedpackages:
					if not self.resultdict[cveid]['affectedpackages'].__contains__(pkg):
						self.resultdict[cveid]['affectedpackages'].append(pkg)

			if rhproducts != None:
				for rhproddict in rhproducts:
					try:
						for newprod,newpkg in rhproddict.iteritems():
							if not self.resultdict[cveid]['rhproducts'].__contains__(newprod):
								self.resultdict[cveid]['rhproducts'][newprod]=list()
								self.resultdict[cveid]['rhproducts'][newprod].append(newpkg)
							else:
								if not self.resultdict[cveid]['rhproducts'][newprod].__contains__(newpkg):
									self.resultdict[cveid]['rhproducts'][newprod].append(newpkg)
					except:
						print 'exception encountered. rhproddict='
						print rhproddict
						print type(self.resultdict[cveid]['rhproducts'])
						raise

			if affectedproducts != None:
				for vendor,proddict in affectedproducts.iteritems():
					if not self.resultdict[cveid]['affectedproducts'].__contains__(vendor):
						self.resultdict[cveid]['affectedproducts'][vendor]=dict()	
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
			self.resultdict[cveid]['rhproducts']=dict()
			if cvescore != None: 
				self.resultdict[cveid]['score']=cvescore
			if cveurl != None:
				self.resultdict[cveid]['url']=cveurl
			self.resultdict[cveid]['mute']='off'
			if affectedpackages != None:
				self.resultdict[cveid]['affectedpackages']=affectedpackages
			if affectedproducts != None:				
				self.resultdict[cveid]['affectedproducts']=affectedproducts
			if descriptions != None:
				self.resultdict[cveid]['descriptions']=descriptions
			if nvddescriptions != None:
				self.resultdict[cveid]['nvddescriptions']=nvddescriptions
			return

	def trimResult(self, products=None, packages=None ,scores=None, cves=None, mute='none'):

		scoredefs=OrderedDict()
		scoredefs['None']={'high':0.0, 'low':0.0}
		scoredefs['Low']={'high':3.9, 'low':0.1}
		scoredefs['Medium']={'high':6.9, 'low':4.0}
		scoredefs['High']={'high':8.9, 'low':7.0}
		scoredefs['Critical']={'high':10.0, 'low':9.0}
		scoredefs['Missing']={'high':11.0, 'low':11.0}

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
					scorezone=scoredefs[score]
					if val['score'] < scorezone['low'] or val['score'] > scorezone['high']:
						numfails+=1
				if numfails == len(scores):
					#this entry fails all specified score requirements
					continue

			if packages != None:
				found=0
				for package in packages:
					for affpkg in val['affectedpackages']:
						if affpkg.startswith(package):
							found=1
							break
					if found == 1:
						break
				if found == 0:
					continue

			if products != None:
				found=0
				for product in products:
					for pdt in val['affectedproducts']:
						if pdt.startswith(product):
							found=1
							break
					if found == 1:
						break

				if found == 0:
					continue

			newresultdict[key]=val

		#outside the loop
		if mute != 'none':
			for entry in newresultdict:
				newresultdict[entry]['mute']=mute
				self.resultdict[entry]['mute']=mute

			with codecs.open('vulnstore.json','w','utf-8') as outfile:
				json.dump(self.resultdict,outfile)
		self.resultdict=newresultdict

	def printMuted(self):
		for key, value in self.resultdict.iteritems():
			if value['mute'] == 'on':
				print key
				print 'Affected packages:-'
				for pkg in value['affectedpackages']:
					print pkg

	def printResult(self, products=None,packages=None,scores=None):
		
		cvelist=list()
		proddict=OrderedDict()
		pkglist=list()
		scorelist=list()
				
		for key,val in self.resultdict.iteritems():
			if self.resultdict[key]['mute'] == "on":
				continue

			scorelist.append(val['score'])

			if not cvelist.__contains__(key):
				cvelist.append(key)
				
			for pkg in val['affectedpackages']:
				if not pkglist.__contains__(pkg):
					pkglist.append(pkg)

		#if packages != None:
		for pkg in pkglist:
			print pkg
		
		#if products != None:
		print "\nRedhat Product Info\n"
		for pd,pkg in proddict.iteritems():
			print '%s:%s'%(pd,pkg)
		
		with open ('listedscores','w') as outfile:
			for score in scorelist:
				outfile.write('%s\n'%score)

		with open ('listedpkgs','w') as outfile:
			for pkg in pkglist:
				outfile.write('%s\n'%pkg)
		with open ('listedcves','w') as outfile:
			for cve in cvelist:
				outfile.write('%s\n'%cve)
			
		print "\nCVE Details"
		print "-----------"
		for cve in cvelist:
			print cve
			for desc in self.resultdict[cve]['descriptions']:
				print desc

class CVEDetails:
	def __init__(self):
		self.name=''
		self.packages=list()
		
class CVECheck:
	def __init__(self):
		self.sources=OrderedDict()
		self.resObj=Result()
		self.fallback=dict()
		self.sources['redhat']='https://access.redhat.com/labs/securitydataapi/cve.json'
		self.sources['nvd']='thisdoesntreallymatter'
		self.fallback['redhat-cve.json']='redhat-cve.json.tmpl'
		self.vulnstore='vulnstore.json'
		self.vulnobj=OrderedDict()
		self.cksumfile='sha256sums'
		self.noconnectivity=0
		self.rhproducts=dict()
		self.rhproducts['Red Hat Enterprise Linux 5']='RHEL5' 
		self.rhproducts['Red Hat Enterprise Linux 6']='RHEL6' 
		self.rhproducts['Red Hat Enterprise Linux 7']='RHEL7' 
		self.rhproducts['Red Hat Enterprise Linux 8']='RHEL8'

	def setupRef(self,refdict):
		refdict['source']='local'
		refdict['tense']='unspecified'
		refdict['figureofspeech']='unspecified'
		refdict['additionalattribute']='unspecified'
		refdict['definitions']=list()
		return refdict

	def updatefromNVD(self):
		urlobj = urllib.URLopener()
		channelinfo=dict()
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
				retval,sha256sum=self.computeChecksum(channel)
				if sha256sum != channelinfo[channel]['sha256sum']:
					print "Update available for %s"%channelinfo[channel]
					urlobj.retrieve(channelinfo[channel]['url'],channelinfo[channel]['zip'])
					with gzip.GzipFile(channelinfo[channel]['zip'], 'rb') as f:
						fcontent = f.read()
					with open(channel,'wb') as out:
						out.write(fcontent)
					os.remove(channelinfo[channel]['zip'])
				#insert into sha256sums if lines not present
				retval=self.checkforChanges(fname=channel)
				if retval != 0:
					changed=1
				if retval == -1:
					print "Catastrophic failure. FS error?"
					sys.exit(-1)
		except:
			print "Could not fetch NVD metadata files; check internet connectivity. Your CVE store could not be updated."
			self.noconnectivity=1
			#no metadata files. read the local nvd files
			try:
				for channel in channelinfo:
					retval=self.checkforChanges(fname=channel)
					if retval == -1:
						raise
			except:
				raise
				print "Unable to read local nvd files. Execute initnvd.sh"
				sys.exit(-1)
			#this is the unupdated case. Local nvd files are available for reading
			return(0,channelinfo)
		#this is the potentially updated case. Local nvd files are available for reading
		if changed == 1:
			return(1,channelinfo)
		else:
			return(0,channelinfo)

	def readNVDfiles(self,channelinfo,retval):
		try:
			with open('vulnstore.json','r') as inp:
				donothing=1
		except:
			print 'No vuln store file found. Initializing from whatever we have.'
			retval=1
		if retval == 0:
			print 'Nothing has changed from the last invocation. Will read from local store and proceed'
			retval,self.resObj.resultdict=self.readStore(self.vulnstore,self.resObj.resultdict)
			return
		
		exceptioncount=0
		idxcount=0
		basescorex=0
		descx=0
		
		for channel in channelinfo:
			pobj=dict()
			retval,pobj=self.readStore(channel,pobj)
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
				try:
					inputs['cveid']=cveitem['cve']['CVE_data_meta']['ID']
				except:
					idxcount+=1
				try:
					inputs['cvescore']=cveitem['impact']['baseMetricV3']['cvssV3']['baseScore']
				except:
					basescorex+=1
				try:
					for desc in cveitem['cve']['description']['description_data']:
						inputs['nvddescriptions'].append(desc['value'])
				except:
					descx+=1
					continue
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
					
					self.resObj.addResult(**inputs)
				except:
					exceptioncount+=1
					raise
					continue
		print 'exceptioncount is %d'%exceptioncount
		print idxcount,basescorex,descx
		print len(self.resObj.resultdict)
		self.writeStore(self.vulnstore,self.resObj.resultdict)
				
	def updatefromRedhat(self,url):
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

		aggregobj=list()
		for pkg in pkglist:
			url=self.sources['redhat']
			url+='?package=%s'%pkg
			if self.noconnectivity == 1:
				break
			try:
				cveintobj=json.load(urllib2.urlopen(url),object_pairs_hook=OrderedDict)
				for entry in cveintobj:
					aggregobj.append(entry)
				self.writeStore(redhatjson,aggregobj)
			except:
				print 'cannot update CVEs for redhat packages; check internet connectivity.'
				self.noconnectivity=1

		return(redhatjson)

	def readRedhatfiles(self,redhatjson):
		retval=self.checkforChanges(fname=redhatjson)
		if retval == 0: 
			initstore=0
			retval,self.resObj.resultdict=self.readStore(self.vulnstore,self.resObj.resultdict)
			if retval == -1:
				initstore=1
		else:
			initstore=1

		if initstore == 1:
			rjobj=OrderedDict()	
			retval,rjobj=self.readStore(redhatjson,rjobj)
			if retval != 0:
				sys.exit(-1)
			inputs=dict()
			inputs['cveid']=None	
			inputs['cveurl']=None	
			inputs['cvescore']=None	
			inputs['affectedpackages']=list()	
			inputs['affectedproducts']=None
			inputs['rhproducts']=list()	
			inputs['descriptions']=list	
			inputs['details']=None	
			inputs['mitigation']=None
			inputs['nvddescriptions']=None
			for rj in rjobj:
				try:
					inputs['cveid']=rj['CVE']
					inputs['cveurl']=rj['resource_url']
					inputs['affectedpackages']=rj['affected_packages']
					inputs['cvescore']=rj['cvss3_score']
				except:
					moveon=1

				if inputs['cvescore'] == None:
					inputs['cvescore']='Missing'
				if self.noconnectivity == 0:
					try:
						print 'pulling down %s'%(inputs['cveurl'])
						cveobj=json.load(urllib2.urlopen(inputs['cveurl']))
					except:
						print 'Failure to fetch CVE details. All data fields may not be available'

					#RedHat CVE files are very inconsistent with fields. 
					try:
						inputs['details']=cveobj['details']
					except:
						donothing=1
					try:
						inputs['descriptions'].append(cveobj['bugzilla']['description'])
					except:
						inputs['descriptions'] = None
					try:
						intputs['mitigation']=cveobj['mitigation']
					except:
						donothing=1

					apdict=OrderedDict()
					for pstate in cveobj['affected_release']:
						if not type(pstate) == dict:
							continue
						if not pstate.__contains__('package'):
							continue
						try:
							apdict[self.rhproducts[pstate['product_name']]]=pstate['package']
						except:
							print 'didnt find product %s'%pstate['product_name']
							apdict[pstate['product_name']]=pstate['package']

					inputs['rhproducts'].append(apdict)
				if type(inputs['descriptions']) != str and type(inputs['descriptions']) != type(None):
					print type(inputs['descriptions'])
					print inputs['descriptions']
					print inputs['cveid']
					sys.exit(-1)	
				self.resObj.addResult(**inputs)
			try:
				self.writeStore(self.vulnstore,self.resObj.resultdict)
			except:
				print 'ran into our issue'
				print type(self.resObj.resultdict)
				for key, val in self.resObj.resultdict.iteritems():
					print key,val
				raise
			return
		else: # nothing to do here. resultdict has been initialized from vuln object directly, and there are no more changes.
			return
	
	def computeChecksum(self,fname):
		try:
			sha256sum=''
			with open(fname,'rb') as infile:
				sha256sum=sha256(infile.read()).hexdigest()
			return(0,sha256sum)
		except:
			return(-1,sha256sum)
			

	def checkforChanges(self,url=None,fname=None):
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
			retval,sha256sum=self.computeChecksum(fname)
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
				return(0)

	def updateStore(self):
		for key, val in self.sources.iteritems():
			if key == 'redhat':
				continue
				#jsonfile=self.updatefromRedhat(val)
				#self.readRedhatfiles(jsonfile)
			if key == 'nvd':
				retval,channelinfo=self.updatefromNVD()
				self.readNVDfiles(channelinfo,retval)

	def readStore(self,jsonfile,jsonobj):
		try:
			print 'reading in file %s'%jsonfile
			with codecs.open(jsonfile,'r','utf-8') as infile:
				jsonobj=json.load(infile)
		except:
			return(-1,jsonobj)
		return(0,jsonobj)

	def writeStore(self,jsonfile, jsonobj):
		with codecs.open(jsonfile,'w','utf-8') as outfile:
			json.dump(jsonobj,outfile)
	
aparser=argparse.ArgumentParser(description='A tool to fetch and update a local vulnerability store against select sources of vulnerability information. It can be queried for specific CVEs, by severity or product name, or a combination. Entries can be marked as "seen" to allow one to "mute" alerts for onal words into the corpus.')
aparser.add_argument("-c", "--cve", type=str, default='none',help='output information about specified CVE or comma-separated list of CVEs. Cannot be combined with any other filter/option.')
aparser.add_argument("-s", "--severity", type=str,default='none',help='filter results by severity level. Valid levels are "None", "Low", "Medium", "High", and "Critical".') #lookup by severity level
aparser.add_argument("-pkg", "--package", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by package, e.g. httpd
aparser.add_argument("-m", "--mute", type=str, default='none',help='set mute on or off, to silence/unsilence reporting. Must be used in combination with one or more filters, and must include -pkg') #mark results as seen or unseen
aparser.add_argument("-d", "--disp-mute", type=str, nargs='?',default='none',help='display muted entries. Any other options are ignored, when combined with this option.') #mark results as seen or unseen

args=aparser.parse_args()
cve=args.cve
severity=args.severity
package=args.package
mute=args.mute
disp_mute=args.disp_mute

argsdict=dict()
argsdict['scores']=None
argsdict['packages']=None
argsdict['cves']=None
resobj=Result()
cvcobj=CVECheck()

if severity != 'none':
	scores=severity.split(',')
	for score in scores:
		if score != 'None' and score != 'Low' and score != 'High' and score != 'Medium' and score != 'Critical' and score != 'Missing':
			print 'Invalid severity level!'
			sys.exit(-1)
	argsdict['scores']=scores


if package != 'none':
	argsdict['packages']=package.split(',')

if mute != 'none':
	if mute != 'on' and mute != 'off':
		print 'Value for mute flag can only be "off" or "on"'
		sys.exit(-1)
	if package == 'none' and cve == 'none':
		print 'Mute flag requires the use of the --pkg or the --cve option. If both are specified, --pkg is ignored.'
		sys.exit(-1)
	argsdict['mute']=mute

cvcobj.updateStore()
if disp_mute != 'none':
	cvcobj.resObj.printMuted()
	sys.exit(0)

if cve != 'none':
	argsdict['cves']=cve.split(',')
	argsdict['scores']=None
	argsdict['packages']=None

argsdict['products']=None
cvcobj.resObj.trimResult(**argsdict)
cvcobj.resObj.printResult(scores=argsdict['scores'],products=None,packages=argsdict['packages'])
