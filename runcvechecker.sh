#!/bin/bash

cd cvechecker || exit -1 #copy this script to outside the cvechecker directory, to run from a cron etc
if [ -f cverun ]; then
	exit -1;
fi
touch cverun

if [ ! -s cvechecker.conf ]; then
    echo "Copy the cvechecker.conf.template file as cvechecker.conf, populate it with correct values and run again";
    exit -1;
fi

pkgs=`grep packages cvechecker.conf|cut -d '=' -f2`
keywords=`grep keywords cvechecker.conf|cut -d '=' -f2`
recips=`grep alertmail_recipient cvechecker.conf|cut -d '=' -f2`
sender=`grep alertmail_sender cvechecker.conf|cut -d '=' -f2`
port=`grep mailserver_port cvechecker.conf|cut -d '=' -f2`
server=`grep mailserver_host cvechecker.conf|cut -d '=' -f2`

python cvechecker.py -p $pkgs -k $keywords >alertout
python cvechecker.py -c CVE-2015-7550 >alertout
if [ -s alertout ]; then
	bash splitreports.sh alertout "$sender" "$recips" $server $port
fi

if [ -s alertout ]; then
	python cvechecker.py -p $pkgs -k $keywords -m on
fi
rm cverun
