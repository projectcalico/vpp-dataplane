# Host Policies in Calico

This document summarizes the behavior of calico (iptables) towards traffic
to/from a host, in different cases. The purpose of this is to check whether
calico/vpp maintains feature parity.
What is the awaited behavior in the different cases in Calico Linux? Does
calicovpp maintain same features?

We have local vs external (local is between local pods and their host, external
is coming from outside)
We have terminated vs forwarded (terminated has the host address as
destination, forwarded has another one that can be a local or external pod for
example, typically a backend of a nodePort service).

## LOCAL TRAFFIC

### Endpoints to host

DEFAULTENDPOINTTOHOSTACTION (EPHA) is an env var that controls (at the host
level, ingress) whether local pods can access their host or not. This variable
has priority over everything, even failsafe ports.
If it is set to ACCEPT (default value when using operator), traffic from pods
to their host is always accepted and this behavior cannot be changed using
explicit policies on the host.
If it is set to DROP (by removing operator and changing env var), traffic from
pods to their host is always dropped, this behavior cannot be changed using
explicit policies on the host.
So, this traffic can never be controlled using policies.

### Host to endpoints

Traffic from host to local pods is always allowed, this behavior can never
change, it has priority over any other behavior. The purpose of this is health
check of pods.

## EXTERNAL TRAFFIC

### Nothing created (no host endpoint)

All traffic works.

### HEP (Host Endpoint) created on a node without any policies (empty hep)

#### Ingress

* External traffic that is terminated is DROPPED (except failsafe)
* External traffic that is forwarded is ALLOWED.

#### Egress

* Outbound traffic to outside is dropped (except failsafe)

So empty host endpoint results in denying external traffic (not forwarded one).
Note: ingress and egress policies are treated separately, so if ingress is
empty, we deny ingress traffic regardless of egress, and vice versa.

### HEP created with an ingress policy denying destination port 3000 (applyOnForward=false)

* External traffic (having port 3000 as destination) that is terminated is DROPPED
* External traffic (having port 3000 as destination) that is forwarded is ALLOWED

### HEP created with an ingress policy denying destination port 3000 (applyOnForward=true)

* External traffic (having port 3000 as destination) that is terminated is
DROPPED
* External traffic (having port 3000 as destination) that is forwarded is
DROPPED (in the case of a nodePort service, 3000 is the port that the backend
has its application running on, not the nodeport)
