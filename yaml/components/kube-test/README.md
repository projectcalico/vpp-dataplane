# Kube-test kustomize component

This component transforms the standard CalicoVPP daemonset for use
by the VPP `extras/kube-test` test harness (and other consumers that
share its constraints).

This file documents the **split-image** variant of the component used
on release branches `<= v3.32`. `master`/`>= v3.33` ships a unified-image
variant where the agent container reuses `calicovpp/vpp` with an explicit
`command: ["/bin/calico-vpp-agent"]` override. Either way, the consumer
just sees a working manifest.

## What this component owns (consumer-agnostic, layout-aware)

* Image references (registry `localhost:5000`, `imagePullPolicy: Always`).
* The split-image layout: the `vpp` container uses `calicovpp/vpp` and the
  `agent` container uses `calicovpp/agent` with no command override.
* The path to the in-tree VPP build output that is bind-mounted into the
  containers as `/repo/vpp-manager/vpp_build/...`.
* The tigera-operator `Installation` and `APIServer` CRs that kube-test
  needs to bootstrap Calico.

When the layout changes, **only this component** (and its base manifest)
needs to change. Consumers stay untouched.

## What the consumer (e.g. VPP kube-test) owns

Only the following placeholders survive in the emitted manifest and must
be substituted by the consumer at apply-time (e.g. via `envsubst`):

| Placeholder                   | Owner / typical source               |
| ----------------------------- | ------------------------------------ |
| `${CALICOVPP_VERSION}`        | image tag (`kt-master`, `v3.31.0`)   |
| `${HOME}`                     | host path for calicovpp checkout     |
| `${ADDITIONAL_VPP_CONFIG}`    | per-test extra VPP startup CLI       |
| `${CALICOVPP_ENABLE_MEMIF}`   | per-test memif feature toggle        |
| `${CALICO_NETWORK_CONFIG}`    | per-test calico-network override     |
| `${CALICOVPP_INTERFACE}`      | baremetal-only: uplink NIC name      |

The consumer MUST NOT need to know which image name to use, what the
in-repo path of the VPP build directory is or any other CalicoVPP
internal detail.
