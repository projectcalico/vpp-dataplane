#!/bin/bash
iperf -V -s -u -l1000 -p 5003 $@ &
iperf -V -s           -p 5001 $@
