# Developper documentation

## Typical commands

As a developper, the main Makefile targets

````console
# build golang agents
make build 

# build docker images (including VPP - this might take a while the first time) 
make image DEBUG=true

# Build images and create a local kind cluster with them
make kind DEBUG=true
````

VPP interaction targets :

````console
# Clone VPP as of the latest commit
make cherry-vpp

# rebuild the golang API bindings
make goapi
````

## Additional guides

- [Developper guide](developper_guide.md)
- [Kind](kind.md)
- [testing BGP filtering](bgp_filtering.md)
