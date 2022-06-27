
## Upgrade process

We match the Calico/VPP version to a given Calico version.
in order to upgrade proceed as follows :

* Upgrade go.mod with the newer version of projectcalico/calico :
  - Get the appropriate commit hash for the new version in the https://github.com/projectcalico/calico repository
  - run `go get github.com/projectcalico/calico@<commit hash>`
  - This will change the go.mod & go.sum with `github.com/projectcalico/calico v1.11.0-cni-plugin.0.{SOMEDATE}-{SOMEHASH}`
  - Edit go.mod to make it `v0.0.0-{SOMEDATE}-{SOMEHASH}`, remove it from go.sum and run `go mod download github.com/projectcalico/calico` to fixup go.sum
  - Add comments e.g. `// v3.23.0` to make the commit hash explicit
  - Update the `replace ()` section with the replacement found in github.com/projectcalico/calico/go.mod (those for `google.golang.org/grpc` and `k8s.io/*` in the main section)
* Upgrade go.mod with the newer version of projectcalico/api :
  - Get the appropriate commit hash for the new version in the https://github.com/projectcalico/api repository
  - run `go get github.com/projectcalico/api@<commit hash>`
  - This will change the go.mod & go.sum with `github.com/projectcalico/calico v0.0.0-{SOMEDATE}-{SOMEHASH}`
  - Patch the `replace ()` with the updated date & hash strings `github.com/projectcalico/api => github.com/projectcalico/api v0.0.0-{SOMEDATE}-{SOMEHASH} // v3.23.0`
  - Add comments e.g. `// v3.23.0` to make the commit hash(s) explicit
* Upgrade the generated protobuf interface :
  - Change the versions in `./calico-vpp-agent/proto/Makefile`
  - Check if protoc is installed on your system (instructions for installing it are below)
  - Run `make proto` to download the newer definitions and genereate the bindings


## Installing protoc

In order to install protoc, do the following :
````
mkdir -p protoc
cd protoc
wget https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-osx-x86_64.zip
unzip protoc-${PROTOC_VERSION}-osx-x86_64.zip
rm protoc-${PROTOC_VERSION}-osx-x86_64.zip
go get -u github.com/gogo/protobuf/protoc-gen-gogo@v1.3.2
````

* `protoc` is installed in `./protoc/bin/protoc`
* `protoc-gen-go` is installed in `$GOPATH/bin/protoc-gen-go`