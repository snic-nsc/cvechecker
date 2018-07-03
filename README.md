# What does this tool do?

- `cvechecker` can be used in two ways:
    - Perform dynamic lookups on the CVE store it setups, restricting the results on the basis of user-specified filters (CVE id, product-name, keyword, CVE severity etc)
    - Scripted execution to generate alerts against prespecified lists of packages and keywords, which can then be emailed to administrators.
- It supports automatic muting, which can be used to generate a single alert per every new issue.
- If you wish to display results for a search, including those that may have been muted before, add the `-d` flag.

# Requirements

- Python 3
- Ensure you have the python-argparse and python-simplejson packages installed on the system.
- If you are using a custom python installation, you need to have argparse and simplejson packages installed.
    - pip install -r requiredpackages

# Python 2.7 support

- Release v1.08-p2 of cvechecker is the last release for Python 2.7; active development will now only continue for Python 3.
- Functionality-wise, release v1.09 (for python3) is exactly the same as release v1.08-p2 (for python2); for later tags, check the commit messages.
- If there are any fixes for bugs present in the v1.08-p2 release, there will be a new tags which will have the -p2 designation, but these will be in the p2 branch.
- No backports of new features will be made for the p2 branch.

# Configuration and Deployment

- CVE checker uses NVD vulnerability feeds (json) and Redhat cvemap.xml as sources to build the vulnerability store.
- Inspect the nvdchannels.conf file to add/remove any more feeds from NVD;
- Execute firstuse.sh prior to first run.
- Execute ./cvechecker.py -u , to fetch required files and build the local vuln store.
- The last line of the output shows the number of entries in your newly constructed CVE store. If everything's gone well, it should be a rather large number. The output looks like this:

```
[pchengi@esg-idx cvechecker]$ ./cvechecker.py -u
Redhat CVE xml updated successfully.
Update available for {'url': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.gz', 'sha256sum': '8522e47f82752ba18ed01a5bc23b3d5c89c5b171bfefc04c80f9d74276067b95', 'metaurl': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.meta', 'zip': 'CVE-2018.json.gz', 'metafname': 'CVE-2018.json.meta'}
Could not look up old checksum for file CVE-2018.json. Will add
Update available for {'url': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2017.json.gz', 'sha256sum': '8ee3c2267f9682a1cc4be9cdd9f43ecbd09b9f1a42da798a71e20f5439e6ecdb', 'metaurl': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2017.meta', 'zip': 'CVE-2017.json.gz', 'metafname': 'CVE-2017.json.meta'}
Could not look up old checksum for file CVE-2017.json. Will add
Update available for {'url': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2016.json.gz', 'sha256sum': '2195b5baf2eeb6694fd6c43d3ce73fe756e3471f049f680bef2fb7d365af8bac', 'metaurl': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2016.meta', 'zip': 'CVE-2016.json.gz', 'metafname': 'CVE-2016.json.meta'}
Could not look up old checksum for file CVE-2016.json. Will add
Update available for {'url': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2015.json.gz', 'sha256sum': 'bd2e495c7d897a075dba900b1f72b42f4793a2ad345ee50e55ee5970cb6b8ece', 'metaurl': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2015.meta', 'zip': 'CVE-2015.json.gz', 'metafname': 'CVE-2015.json.meta'}
Could not look up old checksum for file CVE-2015.json. Will add
Update available for {'url': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz', 'sha256sum': '3e9b7d9c5f40d9338b427941b232d91b2549ae7f8ff13372fddb0a859ff3cef1', 'metaurl': 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.meta', 'zip': 'CVE-Modified.json.gz', 'metafname': 'CVE-Modified.json.meta'}
Could not look up old checksum for file CVE-Modified.json. Will add
48358
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
- The runcvechecker.sh script, and other helper scripts (splitreports.sh, mailsend.py) are available in this repo.
- Remember to setup the cvechecker.conf file with correct values (using cvechecker.conf.template as a template, for syntax etc) before running runcvechecker.sh.

- If you are looking up a product/keyword for the first time, or if you've never muted the results of your search, their status will show up as 'Fresh'; if the results have been muted, the status will reflect 'Seen', and if there's been any update since the last time it entered the system and/or muted, the status would say 'Update'.
```
[pchengi@esg-idx cvechecker]$ ./cvechecker.py -p irods
---BEGIN REPORT---
CVE-2017-8799
=============
https://nvd.nist.gov/vuln/detail/CVE-2017-8799

Status: Fresh
Score 9.8 (Critical)
Last Modification date: 2017-05-17 19:33

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
CONFIRM    
https://github.com/irods/irods/issues/3452    
---END REPORT---
```

- After muting (./cvechecker.py -p irods -m on), you could display it by using the -d flag (display-muted); the output will note that this is a muted entry, and will note the date it was last muted on. The status is also shown as 'Seen'.

```
[pchengi@esg-idx cvechecker]$ ./cvechecker.py -p irods -d
Printing muted entry
Record insertion date: 2018-06-29 07:41
Record muted date: 2018-06-29 07:47
---BEGIN REPORT---
CVE-2017-8799
=============
https://nvd.nist.gov/vuln/detail/CVE-2017-8799

Status: Seen
Score 9.8 (Critical)
Last Modification date: 2017-05-17 19:33

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
CONFIRM    
https://github.com/irods/irods/issues/3452    
---END REPORT---
```
