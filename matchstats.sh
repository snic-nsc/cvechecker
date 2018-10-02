#!/bin/bash
if [ $# -lt 1 ]; then
    echo "You need to specify the report file";
    exit -1;
fi
reportfile=$1
nummatches=`grep BEGIN $reportfile|wc -l`;
echo "Total number of matching CVEs: $nummatches";
echo -n >matchstats
grep 'Matched on' $reportfile|cut -d ':' -f2-|sort -u >rawmatches
while read ln; do
    nummatches=`grep "Matched on: $ln" $reportfile|wc -l`;
    echo "$ln:$nummatches" >>matchstats;
done <rawmatches
cat matchstats|sort -t ':' -nk2
rm matchstats rawmatches
