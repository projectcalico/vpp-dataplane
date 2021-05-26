#!/bin/bash
iperf3 -s @$ &
/usr/local/bin/envoy -c /etc/envoy.yaml --service-cluster server # add "-l debug" to DEBUG
