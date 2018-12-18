#!/bin/bash
dt=`date`
cd cvechecker || exit -1 #copy this script to outside the cvechecker directory, to run from a cron etc
if [ -f cverun ]; then
    echo "Run skipped at $dt" >>runlog-cvechecker
	exit -1;
fi
touch cverun
echo "Run initiated at $dt" >>runlog-cvechecker
if [ ! -s cvechecker.conf ]; then
    echo "Copy the cvechecker.conf.template file as cvechecker.conf, populate it with correct values and run again";
    exit -1;
fi

recips=`grep alertmail_recipient cvechecker.conf|cut -d '=' -f2`
sender=`grep alertmail_sender cvechecker.conf|cut -d '=' -f2`
port=`grep mailserver_port cvechecker.conf|cut -d '=' -f2`
server=`grep mailserver_host cvechecker.conf|cut -d '=' -f2`

python3 cvechecker.py -r --last 45 >alertout #will restrict alerts to activity within the last 45 days. Very useful if you add new search parameters and don't want a flood of alerts going back a few years.

if [ -s alertout ]; then
	bash splitreports.sh alertout "$sender" "$recips" $server $port
fi

if [ -s alertout ]; then
	python3 cvechecker.py -r -m on
fi
rm cverun
