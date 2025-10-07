# Installing calicovppctl

``calicovppctl`` is a helper CLI facilitating interactions with a VPP running
in a kubernetes pod.

The following CLIs install the latest ``calicovppctl`` to ``/usr/local/bin``.

````console
docker create --name calicovppctl docker.io/calicovpp/ctl:latest
sudo docker cp calicovppctl:/calicovppctl /usr/local/bin/calicovppctl
docker rm calicovppctl
````
