# Calico/VPP policies

Calico enriches Kubernetes set of policies allowing to have ordering in
policies, deny rules, policies applied to host interfaces, more flexible
match rules. In CalicoVPP, we feed Felix messages to our policy server
(agent component), which then configures VPP to create those policies

They are implemented by the capo plugin (for CAlico POlicies)

- For troubleshooting, please consult [troubleshooting](troubleshooting.md)
- For Host endpoint specifics, please consult [host_endpoints](host_endpoints.md)
- For a usage example, please consult [policies_example](policies_example.md)

## More resources

Other resources can be leveraged to add policies and troubleshooting
is the same.

- [hostendpoint](https://docs.tigera.io/calico/latest/reference/resources/hostendpoint)
- [globalNetworkPolicy](https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy)
