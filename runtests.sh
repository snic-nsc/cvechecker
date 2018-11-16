#!/bin/bash

noupdate=0
if [ "$1" != "" ]; then
    noupdate=1;
fi
_exit(){
    option=$1
    message=$2
    echo "Failed to run cvechecker.py $option. $message";
    exit -1;
}

python3 cvechecker.py >/dev/null 2>&1
if [ $? -ne 0 ]; then _exit "-h" "Check code/environment"; fi
echo "Ran successfully without any options.";

if [ $noupdate -eq 0 ]; then
   python3 cvechecker.py -u >/dev/null 2>&1
   if [ $? -ne 0 ]; then _exit "--update" "Check network connectivity."; fi
   echo "Updated successfully.";
fi

python3 cvechecker.py -e exportedmutes_org
if [ $? -ne 0 ]; then 
_exit "-e exportedmutes_org" "Check code."; fi
echo "Exported existing muting information successfully.";

python3 cvechecker.py -d -m off
if [ $? -ne 0 ]; then _exit "-d -m off" "Check code."; fi
echo "Successfully unmuted all muted entries.";

python3 cvechecker.py -e exportedmutes
numentries=`wc -l exportedmutes|awk '{print $1}'`
if [ $numentries -ne 0 ]; then
    _exit "-e exportedmutes" "Check code."; fi

python3 cvechecker.py -c CVE-2018-1308|grep BEGIN >/dev/null
if [ $? -ne 0 ]; then _exit "-c CVE-2018-1308" "Check code."; fi

echo "Performed a successful lookup on a CVE.";

python3 cvechecker.py -c CVE-2018-1308 -m on
python3 cvechecker.py -e exportedmutes
numentries=`wc -l exportedmutes|awk '{print $1}'`
if [ $numentries -ne 1 ]; then
    _exit "-e exportedmutes" "Check code."; fi

echo "Performed a successful muting on a CVE.";

python3 cvechecker.py -d -m off
python3 cvechecker.py -i exportedmutes_org
if [ $? -ne 0 ]; then 
_exit "-i exportedmutes_org" "Check code."; fi

echo "Successfully reimported all of the orginal muted CVEs.";
python3 cvechecker.py -e exportedmutes

echo "All tests ran okay";
exit 0;
