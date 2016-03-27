#!/bin/bash
cat *.c *.h | egrep -cv '(^$)|(^#(inc)|(prag))|(//)|(^ *\*)|(\\\*)|(/\*)' 
