#!/bin/bash

split_report(){
    tosplit="$1"
    sender="$2"
    recips="$3"
    server="$4"
    port="$5"
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
                		echo -e "$lastcert"|grep -v 'BEGIN REPORT'|grep -v 'END REPORT' >singlereport
                		subj=`head -1 singlereport`;
				status=`grep 'Status:' singlereport|cut -d ' ' -f2`
                score=`grep Score singlereport|head -1|cut -d '(' -f2|cut -d ')' -f1`
                if grep -B2 Nil singlereport |grep Redhat >/dev/null; then
                        prods=`grep 'Product:' singlereport |cut -d ' ' -f2|paste -sd,`
                        if [ "$prods" = "" ]; then
                            matched=`grep 'Matched on' singlereport |cut -d ':' -f2|tr -d ' '`
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

				python mailsend.py --sender "$sender" --recips "$recips" --server $server --port $port --subject "$subject" --body singlereport
			fi;
			lastcert=${lastcert}$line"\n"; 
		fi;
	done
}
if [ $# -lt 1 ]; then
    echo "Need a file with reports to split. Bailing out";
    exit -1;
fi
 
split_report "$1" "$2" "$3" "$4" "$5"
