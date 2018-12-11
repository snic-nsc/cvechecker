#!/bin/bash
dt=`date +%Y%m%d%H%M`
mkdir -p backups
python3 cvechecker.py -e exportedmutes
tar -cvzf backups/backup_$dt.tgz *.json *.xml sha256sums exportedmutes
