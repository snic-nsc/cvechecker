#!/bin/bash

reportfile=$1
oneperline=$2
if [ $# -lt 1 ]; then 
    echo "You need to specify the report file";
    exit -1;
fi
if [ "$oneperline" != "" ]; then
    cves=`grep '^https://nvd.nist.gov/vuln/detail' $reportfile |sed 's/.*\/\(.*\)/\1/'`
else
    cves=`grep '^https://nvd.nist.gov/vuln/detail' $reportfile |sed 's/.*\/\(.*\)/\1/'|paste -sd,`
fi
echo "$cves"
