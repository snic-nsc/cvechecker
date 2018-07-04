# What does this tool do ?

- `cvechecker` can be used in two ways:
    - Perform dynamic lookups on the CVE store it setups, restricting the results on the basis of user-specified filters (CVE id, product-name, keyword, CVE severity etc)
    - Scripted execution to generate alerts against prespecified lists of packages and keywords, which can then be emailed to administrators.
- It supports muting, which can be used to generate a single alert per every new issue, to prevent being inundated with repeated alerts for the same issue(s).

# Requirements

- Python 3
- Ensure you have the python-argparse and python-simplejson packages installed on the system.
- If you are using a custom python installation, you need to have argparse and simplejson packages installed.
    - pip install -r requiredpackages

# Python 2.7 support

- Release v1.10-p2 of cvechecker is intended to be the last release for Python 2.7; active development will now only continue for Python 3.
- Functionality-wise, release v1.11 (for python3) is exactly the same as release v1.10-p2 (for python2); for later tags, check the commit messages.
- If there are any fixes for bugs present in the v1.10-p2 release, there will be a new tags which will have the -p2 designation, but these will be in the p2 branch.
- No backports of new features will be made for the p2 branch.

# Configuration and Deployment

- CVE checker uses National Vulnerability Database (NVD) vulnerability feeds (json) and Redhat cvemap.xml as sources to build the vulnerability store.
- There are two configuration files that determine the behavior of the `cvechecker` program; `nvdchannels.conf` and `cvechecker.conf` files.
- Execute firstuse.sh prior to first run; this sets up an empty vulnerability store json file, an empty file into which checksums of downloaded files would be stored, and it sets up the `nvdchannels.conf` file, using the `nvdchannels.conf.tmpl` as the starting point. 
- Inspect the nvdchannels.conf file to add/remove any more feeds from NVD, and ensure that the entry for`CVE-Modified.json` appears at the bottom of the file, i.e. as the last entry.
- Copy the `cvechecker.conf.template` file as `cvechecker.conf`, and change the values mentioned there, to whatever is appropriate for your setup, with correct values for sender and recipient addresses, and email server details.
- Execute ./cvechecker.py -u , to fetch required files and initialize the local vulnerability store.
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
- Execute ./cvechecker.py (without arguments), to display the help menu.
- Execute ./cvechecker.py -e , to get examples for usage.

# How to use

- `cvechecker` can be used as a tool to look-up 

# Sample crontab entries and run script

Given below is an example on how one can setup regular updates and runs of `cvechecker`. It's very essential that the `cvechecker.py -u` operation is executed regularly, to ensure that the latest known CVE definitions are used by the program. The tool itself can be run either by hand, or if you require a scripted execution, the runcvechecker.sh script not only runs the check in a preconfigured manner, but also emails  alerts to the configured recipients, and finishes by muting the entries which resulted in alert notifications, to prevent a subsequent run of the program from raising alerts for a second time.

# Operations

- `cvechecker` can peform the following tasks
    - update CVE definitions by fetching the latest versions of the vulnerability sources, i.e. the cvemap.xml file from redhat, and the CVE-<chosen-year>.json and CVE-Modified.json files, from NVD.
    - look up a CVE or CVEs from the store, using a filter or combination of available filters,  and printing details about the resulting matches (if any).
    - mute a CVE or CVEs in the store, so they don't get reported again when the same set of search filters are used; if there are any changes or updates that are made to a CVE or CVEs by NVD, or by Redhat, the entries are unmuted, if they were previously muted.

## Filters

- The help menu describes the available filters, and even potential combinations of filters, in a fairly detailed manner. I'll simply list the output here:

````
optional arguments:
  -h, --help            show this help message and exit
  -a [AFTER_DATE], --after-date [AFTER_DATE]
                        only list matches whose last modified date is after
                        the given date. Date format YYYY-MM-DD.
  -c CVE, --cve CVE     output information about specified CVE or comma-
                        separated list of CVEs. Cannot be combined with any
                        other filter/option.
  -d [DISP_MUTE], --disp-mute [DISP_MUTE]
                        display muted entries. --cve or --product filters may
                        be used in conjuction with -d.
  -e [EXAMPLES], --examples [EXAMPLES]
                        display usage examples.
  -k KEYWORD, --keyword KEYWORD
                        filter results by specified keyword/comma-separated
                        list of keywords in CVE description text from NVD. Can
                        be combined with -p, to get a union set.
  -m MUTE, --mute MUTE  set mute on or off, to silence/unsilence reporting.
                        Must be used in combination with one of --product or
                        --cve options
  -n [NO_UPDATE], --no-update [NO_UPDATE]
                        do not connect to fetch updated CVE information
                        (useful while debugging).
  -p PRODUCT, --product PRODUCT
                        filter results by specified product name or comma-
                        separated list of products.
  -r [READ_CONFIG], --read-config [READ_CONFIG]
                        read package and keyword filter values from the
                        configuration file. Additional filters may be provided
                        on the command-line.
  -s SEVERITY, --severity SEVERITY
                        filter results by severity level. Valid levels are
                        "None", "Low", "Medium", "High", and "Critical". Needs
                        to be used with --product.
  -u [UPDATE], --update [UPDATE]
                        update the vulnerability store. Should be run
                        regularly, preferably from a cron.
  -x EXCLUDE, --exclude EXCLUDE
                        suppress reporting for these packages; useful to avoid
                        false-positive matches; ex matching xenmobile for xen
                        filter.
- -c/--CVE: 
````

## Scripted/automated execution

- The run script `runcvechecker.sh` gives an example of how `cvechecker` can be used to perform searches for vulnerabilities against products of interest, and handle emailing of alerts to preconfigured recipients.
- If there are matches against the preconfigured search criteria, the report is broken down into one email per issue, and the alerts are emailed to the preconfigured recipients. Note that it is very important to have correct values setup in the `cvechecker.conf` file, prior to running the `runcvechecker.sh` script. Also, remember that the `runcvechecker.sh` script is to be copied into the parent directory containing the cvechecker directory, and the full path to this script is to be used in the cron, if you wish to automate running of the script with cron.
- After the email alerts (if any) are dispatched, the matching results for that query are then muted, to ensure they don't turn up in the alerts in the subsequent run. If there are any updates to the CVE(s) (by either NVD or Redhat), it is unmuted, if it had been muted earlier. This ensures that updates if any don't go unnoticed, while simultaneously avoiding bombardment of alert notifications for the same issue(s).

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
