#!/bin/bash

POD_NAME=$(kubectl get pods -n monit | grep monit | awk '{print $1}')
kubectl exec -it -n monit ${POD_NAME} -- tail -n 10 /data/metrics.log | \
	awk '{M+=$6;U+=$1;N+=$2;S+=$3;I+=$4;T+=$5;}
		END {
			printf "%.2f;%.2f;%.2f;%.2f;%.2f;%d;%d",U/NR,N/NR,S/NR,I/NR,T/NR,M/NR,NR
		}'
