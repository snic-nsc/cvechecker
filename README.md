# What is `CVEChecker` ?

- `CVEChecker` is a tool that aggregates CVE information from Redhat and the [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds), to setup a local vulnerability store that can be queried offline.
- Vulnerabilities can be looked up on the basis of user-specified parameters such as a product name, keywords in the vulnerability description, or the CVEid itself.
- Filters such as `--afterdate`, `--beforedate`, `--severity`, `--exclude` can be used alongside other search-parameters to sharpen search results, and/or reduce noise.
- CVEs can be whitelisted or muted after analysis, to prevent it from popping up every time; however, if there's been any change to the CVE itself (change in severity score, addition of reference links, or modification in CPE lists), muted CVEs are automatically unmuted, so you get to know if there's any change in the status, or if you need to do anything more.
- `CVEChecker` can be configured to work in a totally automated manner in which it emails alerts once for every new issue, before it auto-mutes it. This is useful if you wish to set it up as an early-warning system, but don't want to get spammed. 


- The `runcvechecker.sh` script allows `CVEChecker` to be setup for automated operations.  An example cron configuration is given below:

```
[pchengi@datil ~]$ crontab -l
PATH=/usr/bin:/usr/local/bin:/usr/local/sbin:/bin
15 * * * * cd /home/pchengi/cvechecker && python3 cvechecker.py -u >/dev/null 2>&1
30 * * * * bash /home/pchengi/runcvechecker.sh
```

# Requirements

- Python 3
- Ensure you have the python-argparse and python-simplejson packages installed on the system.
- If you are using a custom python installation, you need to have argparse and simplejson packages installed.
    - pip install -r requiredpackages

# Python 2.7 support

- Release v1.13-p2 (p2 branch) of `CVEChecker` is intended to be the last release for Python 2.7; active development will now only continue for Python 3.
- Functionality-wise, release v1.13 (for python3) is exactly the same as release v1.13-p2 (for python2); for later tags, check the commit messages.

# Configuration and Deployment

- CVE checker uses National Vulnerability Database (NVD) vulnerability feeds (json) and Redhat cvemap.xml as sources to build the vulnerability store.
- There are two configuration files that determine the behavior of the `CVEChecker` program; `nvdchannels.conf` and `cvechecker.conf` files.
- Execute `firstuse.sh` prior to first run; this sets up an empty vulnerability store json file, an empty file into which checksums of downloaded files would be stored, and it sets up the `nvdchannels.conf` file, using the `nvdchannels.conf.tmpl` as the starting point. 
- Inspect the nvdchannels.conf file to add/remove any more feeds from NVD, and ensure that the entry for`CVE-Modified.json` appears at the bottom of the file, i.e. as the last entry.
- Copy the `cvechecker.conf.template` file as `cvechecker.conf`, and change the values mentioned there, to whatever is appropriate for your setup, with correct values. Email sender and recipient information, email server etc needs to be setup if you wish to use the `runcvechecker.sh` script.
- You can have different configuration files, each setup with different products, keywords, and exclude filters, to check against different product sets. You can specify an alternate configuration file as an argument to the  `-r` option.
- Execute `python3 cvechecker.py -u`  to fetch required files and initialize the local vulnerability store. After the initial setup, perform the `-u` operation regularly, to keep the local vulnerabitily store updated. 
- Copy the `runcvechecker.sh` script to the parent directory of the directory containing the `cvechecker` files.
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
# Manual whitelisting and exporting/importing list of muted CVEs

- It is useful, and sometimes important, to have full control over the whitelisting process, and not have it happen automatically. 
- You might also wish to log comments as to why you whitelisted (muted) a certain CVE.
- Manually whitelisting CVEs is a time-consuming activity, and you might want to export the list of CVEs you have muted, to be able to import it on another installation, or to be able to share it with others interested in the same search parameters.
- The `-m` option controls muting: `-m on` turns muting on and `-m off` turns muting off. Muting can be done on a single CVE, or to a whole set of CVEs that match a defined set of parameters. Use with caution.
- For example, `python3 cvechecker.py -p kernel -m on` mutes all known CVEs related to the package 'kernel'. 
- You can display muted CVEs by using the `-d` option, with or without other search parameters. 
- You can use the `-l` flag with `-m on` to log comments about why you are muting the CVE. This information is exported when you use the `-e` option, to export the list of CVEs you have muted.

````
pchengi@thebeast:~/cvechecker$ python3 cvechecker.py -c CVE-2017-7546 -m on -l
Product name?
postgresql
Reason for muting?
Issue fixed in postgresql-8.4.20-8.el6_9 released in October 2017
pchengi@thebeast:~/cvechecker$ python3 cvechecker.py -e exportedmutes

pchengi@thebeast:~/cvechecker$ cat exportedmutes 
CVE-2017-7546|postgresql|2018-10-02 09:28|Issue fixed in postgresql-8.4.20-8.el6_9 released in October 2017
````
- You can use the exported file containing the muting information to import it onto a fresh system, to get all the CVEs muted instantly. 
- While importing muting information from a file, the muting timestamp is inspected; if a CVE has been modified since the last time it was muted, it won't be muted while importing it.

# Using the whitelist-helper (`-w`)

- If you've generated a report for a certain product or combination of search parameters, you can use the whitelist-helper, to quickly select CVEs for whitelisting (muting). To launch the helper, simply use the same search parameters as you used for the report generation, but include the `-w` flag. 
- The whitelist-helper prompts your response for every listed CVE for the selected search-parameters; you can go through the report in a different terminal while you run the whitelist-helper.
- The default response is Y, which selects the CVE for subsequent muting. 
- You can press Ctrl-C at any point, and you won't lose responses made till that point. 
- The cves selected by you for whitelisting will be written out to `whitelist_out`.
- The whitelist-helper only generates a list of CVEs, and doesn't actually mute/whitelist anything. The output file can be used as input for a subsequent manual muting operation.

````
pchengi@thebeast:~/cvechecker$ python3 cvechecker.py -p struts -w
Whitelist entry CVE-2011-1772?(Y/n)
Whitelist entry CVE-2011-2087?(Y/n)
Whitelist entry CVE-2011-2088?(Y/n)n
Whitelist entry CVE-2013-1965?(Y/n)n
Whitelist entry CVE-2013-1966?(Y/n)^Cbye
pchengi@thebeast:~/cvechecker$ cat whitelist_out 
CVE-2011-1772,CVE-2011-2087

pchengi@thebeast:~/cvechecker$ python3 cvechecker.py --cve --file whitelist_out -m on -l
Product name?
Apache Struts
Reason for muting?
CVEs against older versions of Struts.
pchengi@thebeast:~/cvechecker$ python3 cvechecker.py -e exportedmutes 

pchengi@thebeast:~/cvechecker$ cat exportedmutes 
CVE-2011-1772|Apache Struts|2018-10-02 09:46|CVEs against older versions of Struts.
CVE-2011-2087|Apache Struts|2018-10-02 09:46|CVEs against older versions of Struts.
CVE-2017-7546|postgresql|2018-10-02 09:28|Issue fixed in postgresql-8.4.20-8.el6_9 released in October 2017
````
## Description of filters and the output

- Not all options output information onto standard out; `-m` option, when used without `-l` option, is silent. 
- `--cve` cannot be clubbed with other filters.
- Options such as `--severity` and `--whitelist-helper` need other filters to be used simultaneously.
- When there are matches against the selected search parameters, you'll get the output containing the matches.
- Even if multiple products/keywords match the same CVEs, the output will list the CVE only once, i.e. no duplicates.
- Every CVE is preceeded by `---BEGIN REPORT---` and succeeded by `---END REPORT---`; these headers/footers are used by the helper-script `splitreport.sh`, to chunk the report into one-CVE-per-message format, for easy emailing. 
- Use of the `-d` flag displays only matching results which are already muted. 
- In the report, a CVE can have multiple values for the `Status` field:
    - `Fresh`: this CVE has not been muted since it was added to the local vulnerability store.
    - `Seen`: this CVE has been viewed in the past and muted.
    - `Update`: this CVE has been modified since it was added to the local vulnerability store; changes could include additional references, a change in the CVSSv3 score, or changes in the list of affected products/versions. 
    - `R-Update`: this CVE has been modified since it was added to the local vulnerability store, but the only change is additional references. 
- In the report, the `First seen date` displays the date the entry was added to the local vulnerability store; this could be the date of initialization of the database, in the case of older CVEs.
- The `Last Modification date` displays the date there was the last modification/update to this CVE.

```
pchengi@thebeast:~/cvechecker$ python3 cvechecker.py --cve CVE-2017-7546 -d
Printing muted entry
Record insertion date: 2018-10-02 09:21
Record muted date: 2018-10-02 09:28
---BEGIN REPORT---
CVE-2017-7546 postgresql: Empty password accepted in some authentication methods
================================================================================
https://nvd.nist.gov/vuln/detail/CVE-2017-7546

Status: Seen
Score 9.8 (Critical)
First seen date: 2018-10-02 09:21
Last Modification date: 2018-07-17 18:07

Info from Redhat
----------------

It was found that authenticating to a PostgreSQL database account with an empty password was possible despite libpq's refusal to send an empty password. A remote attacker could potentially use this flaw to gain access to database accounts with empty passwords.
....
````

- If the status is `Update`, a changelog section also appears in the report.

````
pchengi@thebeast:~/cvechecker$ python3 cvechecker.py -c CVE-2018-14678
---BEGIN REPORT---
CVE-2018-14678 xen: Uninitialized state in x86 PV failsafe callback path (XSA-274)
==================================================================================
https://nvd.nist.gov/vuln/detail/CVE-2018-14678

Status: Update
Score 7.8 (High)
First seen date: 2018-09-20 14:20
Last Modification date: 2018-10-01 02:04

Changelog
----------

Present score: 7.8. Previous score: Missing


Info from Redhat
----------------

An issue was discovered in the Linux kernel through 4.17.11, as used in Xen through 4.11.x. The xen_failsafe_callback entry point in arch/x86/entry/entry_64.S does not properly maintain RBX, which allows local users to cause a denial of service (uninitialized memory usage and system crash). Within Xen, 64-bit x86 PV Linux guest OS users can trigger a guest OS crash or possibly gain privileges.
....
````
