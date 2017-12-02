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
		self.state='empty'
		self.resultdict=dict()
		self.cves=list()
	
	def addResult(self, cveid, cvedesc, cvescore, affectedpackages, affectedproducts):
		self.state='filtered'
		if self.resultdict.__contains__(cveid):
			dosomething=1
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
			self.resultdict[cveid]['affectedpackages']=list()
			for pkg in affectedpackages:
				self.resultdict[cveid]['affectedpackages'].append(pkg)
			self.resultdict[cveid]['affectedproducts']=list()
			for pkg in affectedproducts:
				self.resultdict[cveid]['affectedproducts'].append(pkg)

	def trimResult(self,products=None, packages=None ,scores=None):

		scoredefs=OrderedDict()
		scoredefs['None']={'high':0.0, 'low':0.0}
		scoredefs['Low']={'high':3.9, 'low':0.1}
		scoredefs['Medium']={'high':6.9, 'low':4.0}
		scoredefs['High']={'high':8.9, 'low':7.0}
		scoredefs['Critical']={'high':10.0, 'low':9.0}

		newresultdict=dict()
		for key, val in self.resultdict.iteritems():

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
						if package in affpkg:
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
						if product in pdt:
							found=1
							break
					if found == 1:
						break

				if found == 0:
					continue

			newresultdict[key]=val
		self.resultdict=newresultdict

	def printResult(self,products=None,packages=None,scores=None):
		nd=OrderedDict()
		
		cvelist=list()
		prodlist=list()
		pkglist=list()
				
		for key,val in self.resultdict.iteritems():
			if not cvelist.__contains__(key):
				cvelist.append(key)
			for pdt in val['affectedproducts']:
				if not prodlist.__contains__(pdt):
					prodlist.append(pdt)
			for pkg in val['affectedpackages']:
				if not pkglist.__contains__(pkg):
					pkglist.append(pkg)


		if products != None:
			print "Affected Products\n"
			for pd in prodlist:
				print pd

		if packages != None:
			print "\nAffected packages\n"
			for pkg in pkglist:
				print pkg

		print "\nCVE Details\n"
		for cve in cvelist:
			print "%s: %s"%(cve,self.resultdict[cve]['desc'])

class CVEDetails:
	def __init__(self):
		self.name=''
		self.packages=list()
		
class CVECheck:
	def __init__(self,vulnjson):
		self.sources=dict()
		self.sources['redhat']='https://access.redhat.com/labs/securitydataapi/cve.json'
		self.vulnjson=vulnjson
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
			self.checkforChanges(url,'redhat-cve.json')
			#this is where the redhat obj gets initialized

	def checkforChanges(self,url,fname):
		try:
			vulnlist = urllib.URLopener()
			vulnlist.retrieve(url,fname)
		except:
			print 'unable to fetch file %s'%(fname)
		
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
			else:
				with open('sha256sums','w') as outfile:
					for file in cksums:
						outfile.write("%s %s\n"%(cksums[file],file))
		except:
			print "Could not look up old checksums"

	def updateStore(self):
		for key, val in self.sources.iteritems():
			if key == 'redhat':
				self.updatefromRedhat(val)
				#self.readXdxf()

	def readStore(self):
		try:
			with codecs.open(self.vulnjson,'r','utf-8') as infile:
				self.vulnobj=json.load(infile,object_pairs_hook=OrderedDict)
		except:
			print 'json file %s not found. Initializing from scratch'%(self.vulnjson)
			self.readXdxf(dontread=1)
	
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

	def translateWord(self,totrans):
		self.readStore(self.engjson)
		decoded=totrans.decode('utf-8')
		if self.engdict.__contains__(decoded):
			ctr=1
			for meaning in self.engdict[decoded]['definitions']:
				print "%d. %s"%(ctr,meaning)
				ctr+=1
			return(0)
		else:
			self.readStore(self.corpusjson)
			for word,refobj in self.mydict.iteritems():
				for meaning in refobj['definitions']:
					if totrans == meaning:
						print "Possible match for %s: %s"%(totrans,word)
			return(0)
	
	def listWord(self,tolist):
		self.readStore(self.corpusjson)
		decoded=tolist.decode('utf-8')
		if self.mydict.__contains__(decoded):
			print "Word %s exists in the corpus"%(tolist)
			self.recordLookup(tolist,self.mydict[decoded]['definitions'])
			ctr=1
			for meaning in self.mydict[decoded]['definitions']:
				print "%d. %s"%(ctr,meaning)
				ctr+=1
			return(0)
		else:
			return(-1)
		
	def removeWord(self,toremove):
		self.readStore(self.corpusjson)
		decoded=toremove.decode('utf-8')
		if self.mydict.__contains__(decoded):
			print "Word %s exists in the corpus"%(decoded)
			ctr=1
			for meaning in self.mydict[decoded]['definitions']:
				print "%d. %s"%(ctr,meaning)
				ctr+=1
			resp=raw_input("Press 'R' to remove complete listing, or specify number to delete a specify meaning, any other key to quit.\n")
			if resp == '':
				return
			if resp=='R' or resp=='r':
				print 'Removing the listing entirely for %s.'%decoded
				self.mydict.pop(decoded)
				self.writeStore(self.corpusjson)
				return
			intresp=int(resp)
			if intresp > 0 and intresp <= len(self.mydict[decoded]['definitions']):
				popped=self.mydict[decoded]['definitions'].pop(intresp-1)
				print 'Removed %s.'%(popped)
			else:
				print 'Ignoring.'
				return
			if len(self.mydict[decoded]['definitions']) == 0:
				self.mydict.pop(decoded)
				print 'Removed %s as it had no remaining definitions.'%(decoded)
		else:
			print "Word %s does not exist in the corpus."%(decoded)
			return
		self.writeStore(self.corpusjson)

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

	def recordLookup(self,word,meanings):
		try:
			with codecs.open(self.lpjson,'r','utf-8') as infile:
				self.lpdict=json.load(infile,object_pairs_hook=OrderedDict)
		except:
			donothing=1
		if self.lpdict.__contains__(word.decode('utf-8')):
			return
		self.lpdict[word]=meanings
		with codecs.open(self.lookupout,'w','utf-8') as outfile:
			for word,meanings in self.lpdict.iteritems():
				outfile.write(word)
				outfile.write(':\t')
				ctr=1
				for meaning in meanings:
					outfile.write("%s, "%(meaning))
					ctr+=1
				outfile.write('\n')
		with codecs.open(self.lpjson,'w','utf-8') as outfile:
			json.dump(self.lpdict,outfile)
			
		
	def writeStore(self,jsonfile):
		with codecs.open(jsonfile,'w','utf-8') as outfile:
			if jsonfile == "sve-eng.json":
				json.dump(self.mydict,outfile)
			else:
				json.dump(self.engdict,outfile)
				
	def writeOuttxtfile(self):
		self.readStore(self.corpusjson)
		with codecs.open(self.txtout,'w','utf-8') as outfile:
			for key, refdict in self.mydict.iteritems():
				outfile.write(key)
				outfile.write('\n')
				dtrncount=1
				for meaning in refdict['definitions']:
					outfile.write("\t %d. %s\n"%(dtrncount,meaning))
					dtrncount+=1

	def addWord(self,toadd):
		decoded=toadd.decode('utf-8')
		self.readStore(self.corpusjson)
		if self.mydict.__contains__(decoded):
			print "Word %s already exists in the corpus"%(toadd)
			ctr=1
			for meaning in self.mydict[decoded]['definitions']:
				print "%d. %s"%(ctr,meaning)
				ctr+=1
			resp=raw_input('Do you wish to add a new meaning(N/y)\n')
			if resp=='y' or resp=='Y':
				newm=raw_input('Enter new meaning\n')
				self.mydict[decoded]['definitions'].append(newm)
			else:
				return
		else:
			print "Word %s does not exist in the corpus"%(toadd)
			refdict=OrderedDict()
			self.mydict[decoded]=self.setupRef(refdict)
			resp='y'
			while resp == 'y':
				newm=raw_input('Enter the meaning for this word\n')
				self.mydict[decoded]['definitions'].append(newm)
				resp=raw_input('Do you wish to add another meaning(N/y)\n')
		self.writeStore(self.corpusjson)

	def listLocalwords(self):
		self.readStore(self.corpusjson)
		for key,val in self.mydict.iteritems():
			if val['source'] == 'local':
				print "Word %s is present only locally"%(key)


aparser=argparse.ArgumentParser(description='A tool to fetch and update a local vulnerability store against select sources of vulnerability information. It can be queried for specific CVEs, by severity or product name, or a combination. Entries can be marked as "seen" to allow one to "mute" alerts for onal words into the corpus.')
aparser.add_argument("-c", "--cve", type=str, default='none',help='output information about specified CVE or comma-separated list of CVEs. Cannot be combined with any other filter/option.')
aparser.add_argument("-u", "--update", type=str, nargs='?',default='none',help='update the store. Cannot be combined with any other option/filter.') #update store
aparser.add_argument("-s", "--severity", type=str,default='none',help='filter results by severity level. Valid levels are "None", "Low", "Medium", "High", and "Critical".') #lookup by severity level
aparser.add_argument("-p", "--product", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by product
aparser.add_argument("-pkg", "--package", type=str, default='none',help='filter results by specified product name or comma-separated list of products.') #lookup by product
aparser.add_argument("-m", "--mark", type=str, default='none',help='mark resulting matches as "seen" or "unseen". Must be used in combination with one or more filters.') #mark results as seen or unseen

args=aparser.parse_args()
cve=args.cve
update=args.update
severity=args.severity
product=args.product
package=args.package
mark=args.mark

argsdict=dict()
argsdict['scores']=None
argsdict['products']=None
argsdict['packages']=None

cvcobj=CVECheck('vuln.json')
resobj=Result()
resobj.addResult('101','101 dalmations is the description',10.0,['dalmations'],['Dalmations 101'])
resobj.addResult('102','James Cameron is the description',4.0,['titanic'],['Titanic the movie'])
resobj.addResult('102','James Cameron is the description',4.0,['Apache'],['Apache Tomcat'])

if cve != 'none':
	print 'you have entered a CVE lookup request. Sit tight'
	sys.exit(0)

if update != 'none':
	cvcobj.updateStore()
	sys.exit(0)

if severity != 'none':
	scores=severity.split(',')
	for score in scores:
		if score != 'None' and score != 'Low' and score != 'High' and score != 'Medium' and score != 'Critical':
			print 'Invalid severity level!'
			sys.exit(-1)
	argsdict['scores']=scores

if product != 'none':
	products=product.split(',')
	argsdict['products']=products

if package != 'none':
	packages=package.split(',')
	argsdict['packages']=packages



resobj.trimResult(scores=argsdict['scores'],products=argsdict['products'],packages=argsdict['packages'])
resobj.printResult(scores=argsdict['scores'],products=argsdict['products'],packages=argsdict['packages'])
