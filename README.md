# What does this tool do?

- `cvechecker` can be used in two ways:
    - Perform dynamic lookups on the CVE store it setups, restricting the results on the basis of user-specified filters (CVE id, product-name, keyword, CVE severity etc)
    - Scripted execution to generate alerts against prespecified lists of packages and keywords, which can then be emailed to administrators.
- It supports automatic muting, which can be used to generate a single alert per every new issue.
- If you wish to display results for a search, including those that may have been muted before, add the `-d` flag.

# Requirements

- Python 2.7.9+
- If you want to run it on python 2.6.6 (Centos/RHEL6 standard), check out the c6 branch, and ensure you have python-argparse and python-simplejson RPMs installed on the system.
- If you are using a custom python installation, you need to have argparse and simplejson packages installed.
    - pip install -r requiredpackages

# Configuration and Deployment

- CVE checker uses NVD vulnerability feeds (json) and Redhat cvemap.xml as sources to build the vulnerability store. 
- Inspect the nvdchannels.conf file to add/remove any more feeds from NVD;
- Execute firstuse.sh prior to first run.
- Execute ./cvechecker.py -u , to fetch required files and build the local vuln store.
- The last line of the output shows the number of entries in your newly constructed CVE store. If everything's gone well, it should be a rather large number. The output looks like this (it'll have a lot many more lines if you are looking up Redhat packages).

```
[pchengi@esg-idx cvechecker]$ ./cvechecker.py -u
Could not look up old checksum. Will add
Could not look up old checksum. Will add
Could not look up old checksum. Will add
Could not look up old checksum. Will add
Could not look up old checksum. Will add
Could not look up old checksum. Will add
29551
```
- Execute ./cvechecker.py (without arguments), for help.
- Execute ./cvechecker.py -e , to get examples for usage.

# Sample crontab entries and run script

The run script below gives an example of how `cvechecker` can be used to generate a single alert per new CVE; as soon as the output is generated, any results that match the specified search parameters are then muted, to ensure they don't turn up in the alerts in the subsequent cron run. If there are any updates to the CVE(s) (by either NVD or Redhat), it is unmuted, if it had been muted earlier. 

```
[pchengi@datil ~]$ crontab -l
PATH=/usr/bin:/usr/local/bin:/usr/local/sbin:/bin
15 * * * * cd /home/pchengi/cvechecker && python cvechecker.py -u >/dev/null 2>&1
30 * * * * bash /home/pchengi/runcvechecker.sh
```

```
[pchengi@datil ~]$ cat runcvechecker.sh 
#!/bin/bash

pkgs='http_server,tivoli,slurm,postgres,general_parallel_file_system,irods,torque_resource_manager,struts,java,linux_kernel,spectrum_protect,spectrum_scale,mariadb,mysql,nagios,munin,hadoop,zen,qemu,vm_virtualbox,fail2ban,bind'
keywords='InfiniBand,Intel,AMD'

cd cvechecker
python cvechecker.py -p $pkgs -k $keywords
python cvechecker.py -p $pkgs -k $keywords -m on
```
If you are looking up a product/keyword for the first time, or if you've never muted the results of your search, their status will show up as 'Fresh'; if the results have been muted at least once, any updates would result in the status saying 'Update', instead of 'Fresh'.

```
[pchengi@esg-idx cvechecker]$ ./cvechecker.py -p java

---BEGIN REPORT---
CVE-2016-0363 IBM JDK: insecure use of invoke method in CORBA component, incorrect CVE-2013-3009 fix
====================================================================================================
https://nvd.nist.gov/vuln/detail/CVE-2016-0363

Status: Fresh    
Score 8.1 (High)

Info from Redhat
----------------

The com.ibm.CORBA.iiop.ClientDelegate class in IBM SDK, Java Technology Edition 6 before SR16 FP25 (6.0.16.25), 6 R1 before SR8 FP25 (6.1.8.25), 7 before SR9 FP40 (7.0.9.40), 7 R1 before SR3 FP40 (7.1.3.40), and 8 before SR3 (8.0.3.0) uses the invoke method of the java.lang.reflect.Method class in an AccessController doPrivileged block, which allows remote attackers to call setSecurityManager and bypass a sandbox protection mechanism via vectors related to a Proxy object instance implementing the java.lang.reflect.InvocationHandler interface.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-3009.
    

Redhat Platform info
--------------------

Package State
-------------

Affected Package Info
---------------------
ProductName: Red Hat Satellite 5.6 (RHEL v.5)
Package: java-1.7.0-ibm-1:1.7.0.9.40-1jpp.1.el5
advisory_url: https://access.redhat.com/errata/RHSA-2016:1430


ProductName: Red Hat Satellite 5.6 (RHEL v.6)
Package: java-1.7.1-ibm-1:1.7.1.3.40-1jpp.1.el6_7
advisory_url: https://access.redhat.com/errata/RHSA-2016:1430


ProductName: Red Hat Satellite 5.6 (RHEL v.6)
Package: java-1.7.1-ibm-1:1.7.1.4.1-1jpp.1.el6_8
advisory_url: https://access.redhat.com/errata/RHSA-2017:1216


ProductName: Red Hat Satellite 5.7 (RHEL v.6)
Package: java-1.7.1-ibm-1:1.7.1.3.40-1jpp.1.el6_7
advisory_url: https://access.redhat.com/errata/RHSA-2016:1430


ProductName: Red Hat Satellite 5.7 (RHEL v.6)
Package: java-1.7.1-ibm-1:1.7.1.4.1-1jpp.1.el6_8
advisory_url: https://access.redhat.com/errata/RHSA-2017:1216


ProductName: Red Hat Enterprise Linux Supplementary 5
Package: java-1.7.0-ibm-1:1.7.0.9.40-1jpp.1.el5
advisory_url: https://access.redhat.com/errata/RHSA-2016:0702


ProductName: Red Hat Enterprise Linux Supplementary 5
Package: java-1.6.0-ibm-1:1.6.0.16.25-1jpp.1.el5
advisory_url: https://access.redhat.com/errata/RHSA-2016:0708


ProductName: Red Hat Enterprise Linux Supplementary (v. 6)
Package: java-1.7.1-ibm-1:1.7.1.3.40-1jpp.1.el6_7
advisory_url: https://access.redhat.com/errata/RHSA-2016:0701


ProductName: Red Hat Enterprise Linux Supplementary (v. 6)
Package: java-1.6.0-ibm-1:1.6.0.16.25-1jpp.1.el6_7
advisory_url: https://access.redhat.com/errata/RHSA-2016:0708


ProductName: Red Hat Enterprise Linux Supplementary (v. 6)
Package: java-1.8.0-ibm-1:1.8.0.3.0-1jpp.1.el6
advisory_url: https://access.redhat.com/errata/RHSA-2016:1039


ProductName: Red Hat Enterprise Linux Supplementary (v. 7)
Package: java-1.7.1-ibm-1:1.7.1.3.40-1jpp.1.el7
advisory_url: https://access.redhat.com/errata/RHSA-2016:0701


ProductName: Red Hat Enterprise Linux Supplementary (v. 7)
Package: java-1.8.0-ibm-1:1.8.0.3.0-1jpp.1.el7
advisory_url: https://access.redhat.com/errata/RHSA-2016:0716



Info from NVD
-------------

The com.ibm.CORBA.iiop.ClientDelegate class in IBM SDK, Java Technology Edition 6 before SR16 FP25 (6.0.16.25), 6 R1 before SR8 FP25 (6.1.8.25), 7 before SR9 FP40 (7.0.9.40), 7 R1 before SR3 FP40 (7.1.3.40), and 8 before SR3 (8.0.3.0) uses the invoke method of the java.lang.reflect.Method class in an AccessController doPrivileged block, which allows remote attackers to call setSecurityManager and bypass a sandbox protection mechanism via vectors related to a Proxy object instance implementing the java.lang.reflect.InvocationHandler interface.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-3009.

Affected Products
-----------------

Vendor: novell

	Product: suse_linux_enterprise_module_for_legacy_software
	Affected Versions: 12

	Product: suse_manager
	Affected Versions: 2.1

	Product: suse_openstack_cloud
	Affected Versions: 5

	Product: suse_manager_proxy
	Affected Versions: 2.1

	Product: suse_linux_enterprise_software_development_kit
	Affected Versions: 11.0, 12.0

	Product: suse_linux_enterprise_server
	Affected Versions: 11.0, 12.0

Vendor: ibm

	Product: java_sdk
	Affected Versions: 6.0.15.21, 6.1.8.20, 7.0.9.31, 7.1.3.31, 8.0.2.11

Vendor: redhat

	Product: enterprise_linux_hpc_node_supplementary
	Affected Versions: 6.0, 7.0

	Product: enterprise_linux_server_supplementary
	Affected Versions: 6.0, 7.0

	Product: enterprise_linux_workstation_supplementary
	Affected Versions: 6.0, 7.0

	Product: enterprise_linux_desktop_supplementary
	Affected Versions: 5.0, 6.0, 7.0

	Product: enterprise_linux_server_supplementary_eus
	Affected Versions: 6.7z

	Product: enterprise_linux_supplementary
	Affected Versions: 5.0

References
----------

http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00039.html    
SUSE    
SUSE-SU-2016:1299    
http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00040.html    
SUSE    
SUSE-SU-2016:1300    
http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00042.html    
SUSE    
SUSE-SU-2016:1303    
http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00058.html    
SUSE    
SUSE-SU-2016:1378    
http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00059.html    
SUSE    
SUSE-SU-2016:1379    
http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00061.html    
SUSE    
SUSE-SU-2016:1388    
http://lists.opensuse.org/opensuse-security-announce/2016-05/msg00067.html    
SUSE    
SUSE-SU-2016:1458    
http://lists.opensuse.org/opensuse-security-announce/2016-06/msg00002.html    
SUSE    
SUSE-SU-2016:1475    
http://rhn.redhat.com/errata/RHSA-2016-0701.html    
REDHAT    
RHSA-2016:0701    
http://rhn.redhat.com/errata/RHSA-2016-0702.html    
REDHAT    
RHSA-2016:0702    
http://rhn.redhat.com/errata/RHSA-2016-0708.html    
REDHAT    
RHSA-2016:0708    
http://rhn.redhat.com/errata/RHSA-2016-0716.html    
REDHAT    
RHSA-2016:0716    
http://rhn.redhat.com/errata/RHSA-2016-1039.html    
REDHAT    
RHSA-2016:1039    
http://seclists.org/fulldisclosure/2016/Apr/20    
FULLDISC    
20160405 Re: [SE-2012-01] Broken security fix in IBM Java 7/8    
http://seclists.org/fulldisclosure/2016/Apr/3    
FULLDISC    
20160404 [SE-2012-01] Broken security fix in IBM Java 7/8    
http://www-01.ibm.com/support/docview.wss?uid=swg1IX90172    
AIXAPAR    
IX90172    
http://www-01.ibm.com/support/docview.wss?uid=swg21980826    
CONFIRM    
http://www-01.ibm.com/support/docview.wss?uid=swg21980826    
http://www.security-explorations.com/materials/SE-2012-01-IBM-4.pdf    
MISC    
http://www.security-explorations.com/materials/SE-2012-01-IBM-4.pdf    
http://www.securityfocus.com/bid/85895    
BID    
85895    
http://www.securitytracker.com/id/1035953    
SECTRACK    
1035953    
https://access.redhat.com/errata/RHSA-2016:1430    
REDHAT    
RHSA-2016:1430    
https://access.redhat.com/errata/RHSA-2017:1216    
REDHAT    
RHSA-2017:1216    
---END REPORT---
```
