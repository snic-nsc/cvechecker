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

- CVE checker uses NVD vulnerability feeds (json) and Redhat Security API as sources to build the vulnerability store. 
- The Redhat security API data only provides RPM infomation, and fetches files individually per CVE, so you should choose as few redhat packages to monitor as possible; these are specified in the file `advancedcveinfolist.` If you wish to entirely disable Redhat product information fetches, simply change the line like this

```
packages|none
```
- Inspect the nvdchannels.conf file to add/remove any more feeds from NVD;
- Execute firstuse.sh prior to first run.
- Execute ./cvechecker.py -u , to fetch required files and build the local vuln store.
- If you've disabled Redhat product info, you should have only a few lines of output on the terminal, with the last line showing the number of entries in your newly constructed CVE store. If everything's gone well, it should be a rather large number. The output looks like this (it'll have a lot many more lines if you are looking up Redhat packages).

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
[pchengi@esg-idx cvechecker]$ ./cvechecker.py -p irods


CVE-2017-8799
=============

Status: Fresh    
Score 9.8 (Critical)

Info from Redhat
----------------
Nil

Info from NVD
-------------

Untrusted input execution via igetwild in all iRODS versions before 4.1.11 and 4.2.1 allows other iRODS users (potentially anonymous) to execute remote shell commands via iRODS virtual pathnames. To exploit this vulnerability, a virtual iRODS pathname that includes a semicolon would be retrieved via igetwild. Because igetwild is a Bash script, the part of the pathname following the semicolon would be executed in the user's shell.

Affected Products
-----------------

Vendor: irods

        Product: irods
        Affected Versions: 4.1.10, 4.2.0

References
----------

https://github.com/irods/irods/issues/3452    
```
