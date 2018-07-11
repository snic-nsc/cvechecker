#!/bin/bash

split_report(){
    tosplit="$1"
    cve="$2"
    sl=0
	lead='---BEGIN REPORT---'
	end='---END REPORT---'
	numl=`cat $tosplit|tr -d "\r"|wc -l`;
	for i in `seq 1 $numl`; do
		line=`head -$i $tosplit|tail -1`;
		if echo "$line"|grep -e "$lead" >/dev/null; then
			sl=1;
			lastcert="$lead\n"; 
			continue
		fi; 
		if [ $sl -eq 1 ]; then 
			if echo "$line"|grep -e "$end" >/dev/null; then
				sl=0;
				lastcert=${lastcert}$end"";
				echo $lastcert|grep $cve >/dev/null;
                if [ $? -eq 0 ]; then
           			echo -e "$lastcert"|grep -v 'BEGIN REPORT'|grep -v 'END REPORT' >spatout
                    subj=`head -1 spatout`;
                    status=`grep 'Status:' spatout|cut -d ' ' -f2`
                    score=`grep Score spatout|head -1|cut -d '(' -f2|cut -d ')' -f1`
                    if grep -B2 Nil spatout |grep Redhat >/dev/null; then
                        prods=`grep 'Product:' spatout |cut -d ' ' -f2|paste -sd,`
                        if [ "$prods" = "" ]; then
                            matched=`grep 'Matched on' spatout |cut -d ':' -f2|tr -d ' '`
                            if [ "$matched" != "" ]; then
                                subject="${status} ${score} ${subj} Matched on: $matched"
                            else	
                                subject="${status} ${score} ${subj}"
                            fi
                        else
                            subject="${status} ${score} ${subj} ${prods}"
                        fi
                    else
                        subject="${status} ${score} ${subj}"
                    fi
                    echo $subject
                    break;
                fi

            fi;
            lastcert=${lastcert}$line"\n"; 
        fi;
    done
}
if [ $# -lt 1 ]; then
    echo "Need a file with reports to split. Bailing out";
    exit -1;
fi
 
split_report "$1" "$2"
