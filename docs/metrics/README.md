# CalicoVPP metrics

CalicoVPP exposes metrics with a prometheus http endpoint. It is not enabled
by default and can be enabled by setting `prometheusEnabled` to `true` in
`CALICOVPP_FEATURE_GATES`. There are additional configuration parameters under
`CALICOVPP_INITIAL_CONFIG`:

- `prometheusStatsPrefix` - prefix string (default: `cni_projectcalico_vpp_`)
- `prometheusListenEndpoint` - http endpoint port (default: `8888`)
- `prometheusRecordMetricInterval` - metric interval in seconds (default: `5`)

```yaml
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-vpp-config
  namespace: calico-vpp-dataplane
data:
  CALICOVPP_FEATURE_GATES: |-
    { 
      "prometheusEnabled": true
    }

  CALICOVPP_INITIAL_CONFIG: |-
    { 
      "prometheusStatsPrefix": "cni_projectcalico_vpp_",
      "prometheusListenEndpoint": ":8888",
      "prometheusRecordMetricInterval": 5
    }
```

Every metrics is prefixed by the value specified in `prometheusStatsPrefix`.
Keep in mind that all non alphanumeric characters are replaced by underscores.

You can find the full specification for the environment variables
in [config/config.go](https://github.com/projectcalico/vpp-dataplane/blob/master/config/config.go)

## Further documentation

- [Full metrics listing](metrics.md)
- [Example on how to configure a prometheus collector](collector_example.md)
