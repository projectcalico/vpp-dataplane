Usage
=====

Deploy the yaml

```
kubectl add ns trex
kubectl apply -f test.yaml
```

Start trex
```
kubectl exec -it -n trex trex -- bash
$ trex-start
# Ctrl-C to quit
```

Start the console
```
kubectl exec -it -n trex trex -- bash
$ DST_ADDRESS=1.2.3.4 DST_PORT=4444 trex-console
```

In the console, start the packet generation
```
$ trex-console
# (q) to quit
$ start -f /trex-scripts/trex.py -p 0 -m 10mbps
## To show stats (use q to quit)
$ tui
## To update to full speed
$ update -m 100%
## To stop traffic generation
$ stop -a
```