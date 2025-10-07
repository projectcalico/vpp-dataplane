# CalicoVPP metrics

CalicoVPP exposes can expose metrics with a prometheus
http endpoint.

````yaml
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-vpp-config
  namespace: calico-vpp-dataplane
data:
  CALICOVPP_FEATURE_GATES: |-
    { 
      "prometheusEnabled": "true"
    }

  CALICOVPP_INITIAL_CONFIG: |-
    { 
      "prometheusStatsPrefix": "cni_projectcalico_vpp_",
      "prometheusListenEndpoint": ":8888",
      "prometheusRecordMetricInterval": "5s"
    }
````

Every metrics is prefixed by the value specified in
``prometheusStatsPrefix``. Keeping in mind that all non
alphanumeric characters are replaced by underscores.

You can find the full specification for the environment variables
in [config/config.go](https://github.com/projectcalico/vpp-dataplane/blob/master/config/config.go)

## Further documentation

- [Full metrics listing](metrics.md)
- [Example on how to configure a prometheus collector](collector_example.md)
