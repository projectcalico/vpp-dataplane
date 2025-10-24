# Installing calicovppctl

``calicovppctl`` is a helper CLI facilitating interactions with a VPP running
in a kubernetes pod.

The following CLIs install the latest ``calicovppctl`` to ``/usr/local/bin``.

## Using published images

````console
docker create --name calicovppctl docker.io/calicovpp/ctl:latest
sudo docker cp calicovppctl:/calicovppctl /usr/local/bin/calicovppctl
docker rm calicovppctl
````

## Using go

````bash
go install github.com/projectcalico/vpp-dataplane/cmd/calicovppctl/v3@master
````
