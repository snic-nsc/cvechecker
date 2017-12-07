#!/bin/bash

for i in `ls *.tmpl`; do 
after=`echo $i|sed 's/\(.*\).tmpl/\1/'`; 
cp $i $after;
done
