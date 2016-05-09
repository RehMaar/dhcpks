#!/bin/bash

dmesg | sed -n 's/^\[.*\] //; /^dhcpks/!{ s/^/  /;}; /dhcpks:/,$p;' | tee -a log 
