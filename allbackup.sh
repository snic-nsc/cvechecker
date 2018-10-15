#!/bin/bash
dt=`date +%Y%m%d%H%M`
python3 cvechecker.py -e exportedmutes
tar -cvzf allbackup_$dt.tgz *.json *.xml sha256sums exportedmutes
