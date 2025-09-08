# Upgrading Calico

To upgrade the version of calico, follow these steps:

1) Pull the latest calico yaml from [https://docs.projectcalico.org/manifests/calico.yaml](https://docs.projectcalico.org/manifests/calico.yaml)
 and save it in `yaml/base/` (replacing the existing one).
2) Regenerate the calico-vpp manifests with `make TAG=prerelease` in this
directory
3) Upgrade the calico dependencies in go.mod to the version that is used in the
latest Calico release. One way to do so is to go to one of the Calico
repositories (such as <https://github.com/projectcalico/calico/felix>), check
out the latest release tag, and pick the versions from the `go.mod`. Look for
updates to the k8s.io, proto, grpc, projectcalico, containernetworking, etc.
packages. Use `go get <package>@<version>` to upgrade so as not to mess up
go.sum.  It's also a good occasion to upgrade other packages... Note that go
get is sometimes a pita, and asks for the full path to a package instead of
just the module path (eg `go get github.com/projectcalico/api/pkg/lib/numorstring@vvv`
instead of `go get github.com/projectcalico/api@vvv`...)
Finally, run `go mod tidy` at the end and verify everything still builds.
