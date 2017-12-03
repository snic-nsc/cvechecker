#!/usr/bin/env python2
import codecs
import xml.etree.ElementTree as ET
import sys,argparse
from collections import OrderedDict
from hashlib import sha256
import simplejson as json
from numbers import Number
import urllib
reload(sys)
sys.setdefaultencoding('utf-8')

class Result:
	def __init__(self):
		self.resultdict=dict()
	
	def addResult(self, cveid, cvedesc, cvescore, affectedpackages, affectedproducts):
		if self.resultdict.__contains__(cveid):
			for pkg in affectedpackages:
				if not self.resultdict[cveid]['affectedpackages'].__contains__(pkg):
					self.resultdict[cveid]['affectedpackages'].append(pkg)
			for pkg in affectedproducts:
				if not self.resultdict[cveid]['affectedproducts'].__contains__(pkg):
					self.resultdict[cveid]['affectedproducts'].append(pkg)
			
		else:
			self.resultdict[cveid]=OrderedDict()
			self.resultdict[cveid]['score']=cvescore
			self.resultdict[cveid]['desc']=cvedesc
			self.resultdict[cveid]['mute']='off'
			self.resultdict[cveid]['affectedpackages']=list()
			for pkg in affectedpackages:
				self.resultdict[cveid]['affectedpackages'].append(pkg)
			self.resultdict[cveid]['affectedproducts']=list()
			for pkg in affectedproducts:
				self.resultdict[cveid]['affectedproducts'].append(pkg)

	def trimResult(self,products=None, packages=None ,scores=None, cves=None, mute='none'):

		scoredefs=OrderedDict()
		scoredefs['None']={'high':0.0, 'low':0.0}
		scoredefs['Low']={'high':3.9, 'low':0.1}
		scoredefs['Medium']={'high':6.9, 'low':4.0}
		scoredefs['High']={'high':8.9, 'low':7.0}
		scoredefs['Critical']={'high':10.0, 'low':9.0}

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

	def printResult(self,products=None,packages=None,scores=None):
		
		cvelist=list()
		prodlist=list()
		pkglist=list()
		scorelist=list()
				
		for key,val in self.resultdict.iteritems():
			if self.resultdict[key]['mute'] == "on":
				continue

			scorelist.append(val['score'])

			if not cvelist.__contains__(key):
				cvelist.append(key)
			for pdt in val['affectedproducts']:
				if not prodlist.__contains__(pdt):
					prodlist.append(pdt)
			for pkg in val['affectedpackages']:
				if not pkglist.__contains__(pkg):
					pkglist.append(pkg)

		#if packages != None:
			#print "\nAffected packages\n"
		for pkg in pkglist:
			print pkg
		
		#if products != None:
		#print "Affected Products\n"
		#for pd in prodlist:
		#	print pd
		
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
			print "%s: %s"%(cve,self.resultdict[cve]['desc'])

class CVEDetails:
	def __init__(self):
		self.name=''
		self.packages=list()
		
class CVECheck:
	def __init__(self):
		self.sources=dict()
		self.resObj=Result()
		self.fallback=dict()
		self.sources['redhat']='https://access.redhat.com/labs/securitydataapi/cve.json'
		self.fallback['redhat-cve.json']='redhat-cve.json.tmpl'
		self.vulnstore='vulnstore.json'
		self.vulnobj=OrderedDict()
		self.cksumfile='sha256sums'

	def setupRef(self,refdict):
		refdict['source']='local'
		refdict['tense']='unspecified'
		refdict['figureofspeech']='unspecified'
		refdict['additionalattribute']='unspecified'
		refdict['definitions']=list()
		return refdict

	def updatefromRedhat(self,url):
			redhatjson='redhat-cve.json'
			retval=self.checkforChanges(url,redhatjson)
			#this is where the redhat obj gets initialized
			#if retval == 0, there is no change. Simply read store. If store doesn't exist, initialize afresh.
			if retval == 1 or retval == -1:
				retval,self.resObj.resultdict=self.readStore(self.vulnstore,self.resObj.resultdict)
				if retval != 0: #we have to write out a brand new file
					print 'Initializing brand-new store file'
					rjobj=OrderedDict()	
					retval,rjobj=self.readStore(redhatjson,rjobj)
					if retval != 0:
						sys.exit(-1)
					for rj in rjobj:
						try:
							cveid=rj['CVE']
							cvedesc=rj['resource_url']
							cvescore=rj['cvss3_score']
							affectedpackages=rj['affected_packages']
							affectedproducts=list()
						except:
							cvescore=rj['cvss_score']
						self.resObj.addResult(cveid, cvedesc, cvescore, affectedpackages, affectedproducts)
					self.writeStore(self.vulnstore,self.resObj.resultdict)
					return
				#we are here, which means the vuln object was initialized successfully from the file
				return	
			else: # this is before the vuln object was initialized thhrough the file. No changes though in the defs.
				retval,self.resObj.resultdict=self.readStore(self.vulnstore,self.resObj.resultdict)
				return
	
	def checkforChanges(self,url,fname):
		try:
			urlobj = urllib.URLopener()
			urlobj.retrieve(url,fname)
		except:
			#print 'unable to fetch file %s.'%(fname)
			return(-1)
				
		cksums=OrderedDict()
		try:
			with open(self.cksumfile,'r') as infile:
				lines=infile.readlines()
			for line in lines:
				cksums[line.split(' ')[1].split('\n')[0]]=line.split(' ')[0]
			changed=0
			with open(fname,'rb') as infile:
					sha256sum=sha256(infile.read()).hexdigest()
			if cksums[fname] != sha256sum:
				print "Vulnerability store file %s has been updated."%(fname)
				cksums[fname]=sha256sum
				changed=1
			if changed == 0:
				print "No changes found in vulnerability store file %s"%(fname)
				return(0)
			else:
				with open('sha256sums','w') as outfile:
					for file in cksums:
						outfile.write("%s %s\n"%(cksums[file],file))
				return(1)
		except:
			print "Could not look up old checksums"
			return(-1)

	def updateStore(self):
		for key, val in self.sources.iteritems():
			if key == 'redhat':
				self.updatefromRedhat(val)

	def readStore(self,jsonfile,jsonobj):
		try:
			with codecs.open(jsonfile,'r','utf-8') as infile:
				jsonobj=json.load(infile,object_pairs_hook=OrderedDict)
		except:
			return(-1,jsonobj)
			#self.readXdxf(dontread=1)
		return(0,jsonobj)

	def writeStore(self,jsonfile, jsonobj):
		with codecs.open(jsonfile,'w','utf-8') as outfile:
			json.dump(jsonobj,outfile)
	
	def listWordstartswith(self,tolist):
		self.readStore(self.corpusjson)
		found=0
		for word,refobj in self.mydict.iteritems():
			if tolist.startswith(word):
				found=1
				print "Possible related word %s exists in the corpus"%(word)
				print 'input is %s, word in corpus is %s'%(tolist,word)
				ctr=1
				for meaning in refobj['definitions']:
					print "%d. %s"%(ctr,meaning)
					ctr+=1
		if found == 0:
			print "Word %s does not exist in the corpus"%(tolist)

	def readXdxf(self, dontread=0):
		if dontread == 0:
			self.readStore(self.corpusjson)
			self.readStore(self.engjson)
		try:
			tree=ET.parse(self.svexdxfinp)
			engtree=ET.parse(self.engxdxfinp)
			
		except:
			print "Error parsing xdxf input file. Aborting."
			sys.exit(-1)

		self.root=tree.getroot()
		self.engroot=engtree.getroot()

		for node in self.root[1]:
			if not self.mydict.__contains__(node[0].text):
				print 'new word found: %s'%(node[0].text)
				refdict=OrderedDict()
				self.mydict[node[0].text]=self.setupRef(refdict)
				self.mydict[node[0].text]['source']='lexikon'
			else:
				self.mydict[node[0].text]['source']='lexikon'
			for ele in node[1]:
				if ele.tag == 'dtrn':
					if not self.mydict[node[0].text]['definitions'].__contains__(ele.text):
						print 'new definition %s found for word %s'%(ele.text,node[0].text)
						self.mydict[node[0].text]['definitions'].append(ele.text)

		for node in self.engroot[1]:
			if not self.engdict.__contains__(node[0].text):
				print 'new word found: %s'%(node[0].text)
				refdict=OrderedDict()
				self.engdict[node[0].text]=self.setupRef(refdict)
				self.engdict[node[0].text]['source']='lexikon'
			else:
				self.engdict[node[0].text]['source']='lexikon'
			
			for ele in node[1]:
				if ele.tag == 'dtrn':
					if not self.engdict[node[0].text]['definitions'].__contains__(ele.text):
						print 'new definition %s found for word %s'%(ele.text,node[0].text)
						self.engdict[node[0].text]['definitions'].append(ele.text)
		try:
			self.writeStore(self.corpusjson)
			self.writeStore(self.engjson)
			self.writeOuttxtfile()
			print 'Successfully wrote out de-duped word corpus and xdxf.txt file'
		except:
			print 'Could not write out word corpus or/and xdxf.txt file'

aparser=argparse.ArgumentParser(description='A tool to fetch and update a local vulnerability store against select sources of vulnerability information. It can be queried for specific CVEs, by severity or product name, or a combination. Entries can be marked as "seen" to allow one to "mute" alerts for onal words into the corpus.')
aparser.add_argument("-c", "--cve", type=str, default='none',help='output information about specified CVE or comma-separated list of CVEs. Cannot be combined with any other filter/option.')
aparser.add_argument("-s", "--severity", type=str,default='none',help='filter results by severity level. Valid levels are "None", "Low", "Medium", "High", and "Critical".') #lookup by severity level
aparser.add_argument("-p", "--product", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by product like Apache
aparser.add_argument("-pkg", "--package", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by package, e.g. httpd
aparser.add_argument("-m", "--mute", type=str, default='none',help='set mute on or off, to silence/unsilence reporting. Must be used in combination with one or more filters, and must include -pkg') #mark results as seen or unseen
aparser.add_argument("-d", "--disp-mute", type=str, nargs='?',default='none',help='display muted entries. Any other options are ignored, when combined with this option.') #mark results as seen or unseen

args=aparser.parse_args()
cve=args.cve
severity=args.severity
product=args.product
package=args.package
mute=args.mute
disp_mute=args.disp_mute

argsdict=dict()
argsdict['scores']=None
argsdict['products']=None
argsdict['packages']=None
argsdict['cves']=None
resobj=Result()
cvcobj=CVECheck()

if severity != 'none':
	scores=severity.split(',')
	for score in scores:
		if score != 'None' and score != 'Low' and score != 'High' and score != 'Medium' and score != 'Critical':
			print 'Invalid severity level!'
			sys.exit(-1)
	argsdict['scores']=scores

if product != 'none':
	argsdict['products']=product.split(',')

if package != 'none':
	argsdict['packages']=package.split(',')

if mute != 'none':
	if mute != 'on' and mute != 'off':
		print 'Value for mute flag can only be "off" or "on"'
		sys.exit(-1)
	if package == 'none' and cve == 'none':
		print 'Mute flag requires the use of the --pkg or the --cve option. If both are specified, --pkg is ignored.'
		sys.exit(-1)

cvcobj.updateStore()
if disp_mute != 'none':
	cvcobj.resObj.printMuted()
	sys.exit(0)

if cve != 'none':
	argsdict['cves']=cve.split(',')
	argsdict['scores']=None
	argsdict['products']=None
	argsdict['packages']=None

cvcobj.resObj.trimResult(scores=argsdict['scores'],products=argsdict['products'],packages=argsdict['packages'],cves=argsdict['cves'],mute=mute)
cvcobj.resObj.printResult(scores=argsdict['scores'],products=argsdict['products'],packages=argsdict['packages'])
