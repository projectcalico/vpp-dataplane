module github.com/projectcalico/vpp-dataplane/v3

go 1.21

require (
	github.com/calico-vpp/vpplink v0.0.0-20240117140938-62e485f48c6d
	github.com/census-instrumentation/opencensus-proto v0.4.1
	github.com/containernetworking/plugins v1.3.0
	github.com/gogo/protobuf v1.3.2
	github.com/google/gopacket v1.1.19
	github.com/inconshreveable/mousetrap v1.1.0
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.4.0
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.30.0
	github.com/orijtech/prometheus-go-metrics-exporter v0.0.6
	github.com/osrg/gobgp/v3 v3.20.0
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/api v0.0.0-20231218190037-9183ab93f33e // v3.27.0
	github.com/projectcalico/calico v0.0.0-20231216011042-6334b9da6086 // v3.27.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20230206183746-70ca0345eede
	github.com/vishvananda/netns v0.0.4
	github.com/yookoala/realpath v1.0.0
	go.fd.io/govpp v0.10.0-alpha.0.20240110141843-761adec77524
	go.fd.io/govpp/extras v0.1.1-0.20230330140632-6a7dcb03934f
	golang.org/x/net v0.23.0
	golang.org/x/sys v0.18.0
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.33.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	k8s.io/api v0.27.8
	k8s.io/apimachinery v0.27.8
	k8s.io/client-go v0.27.8
	sigs.k8s.io/controller-runtime v0.14.7
)

require (
	github.com/bennyscetbun/jsongo v1.1.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/evanphx/json-patch v5.7.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.7.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.20.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/golang-collections/collections v0.0.0-20130729185459-604e922904d3 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gnostic v0.7.0 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.4.0 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/k-sone/critbitgo v1.4.0 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/projectcalico/go-json v0.0.0-20161128004156-6219dc7339ba // indirect
	github.com/projectcalico/go-yaml-wrapper v0.0.0-20191112210931-090425220c54 // indirect
	github.com/prometheus/client_golang v1.17.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/sagikazarmark/locafero v0.3.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.10.0 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.17.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.etcd.io/etcd/api/v3 v3.5.10 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.10 // indirect
	go.etcd.io/etcd/client/v3 v3.5.10 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/oauth2 v0.14.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/term v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.4.0 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231106174013-bbf56f31fb17 // indirect
	gopkg.in/go-playground/validator.v9 v9.31.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.110.1 // indirect
	k8s.io/kube-openapi v0.0.0-20231113174909-778a5567bc1e // indirect
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

// We match the Calico/VPP version to a given Calico version. In order to upgrade proceed as follows :
// * Upgrade go.mod with the newer version of projectcalico/calico :
//  - Get the appropriate commit hash for the new version in the https://github.com/projectcalico/calico repository
//  - run `go get github.com/projectcalico/calico@<commit hash>`
//  - This will change the go.mod & go.sum with `github.com/projectcalico/calico v1.11.0-cni-plugin.0.{SOMEDATE}-{SOMEHASH}`
//  - Edit go.mod to make it `v0.0.0-{SOMEDATE}-{SOMEHASH}`, remove it from go.sum and run `go mod download github.com/projectcalico/calico` to fixup go.sum
//  - Add comments e.g. `// v3.23.0` to make the commit hash explicit
//  - Update the `replace ()` section with the replacement found in github.com/projectcalico/calico/go.mod (those for `google.golang.org/grpc` and `k8s.io/*` in the main section)
// * Upgrade go.mod with the newer version of projectcalico/api :
//   - Get the appropriate commit hash for the new version in the https://github.com/projectcalico/api repository
//   - run `go get github.com/projectcalico/api@<commit hash>`
//   - This will change the go.mod & go.sum with `github.com/projectcalico/calico v0.0.0-{SOMEDATE}-{SOMEHASH}`
//   - Patch the `replace ()` with the updated date & hash strings `github.com/projectcalico/api => github.com/projectcalico/api v0.0.0-{SOMEDATE}-{SOMEHASH} // v3.23.0`
//   - Add comments e.g. `// v3.23.0` to make the commit hash(s) explicit

replace (
	k8s.io/api => k8s.io/api v0.27.6
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.27.6
	k8s.io/apimachinery => k8s.io/apimachinery v0.27.6
	k8s.io/apiserver => k8s.io/apiserver v0.27.6
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.27.6
	k8s.io/client-go => k8s.io/client-go v0.27.6
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.27.6
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.27.6
	k8s.io/code-generator => k8s.io/code-generator v0.27.6
	k8s.io/component-base => k8s.io/component-base v0.27.6
	k8s.io/component-helpers => k8s.io/component-helpers v0.27.6
	k8s.io/controller-manager => k8s.io/controller-manager v0.27.6
	k8s.io/cri-api => k8s.io/cri-api v0.27.6
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.27.6
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.27.6
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.27.6
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.27.6
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.27.6
	k8s.io/kubectl => k8s.io/kubectl v0.27.6
	k8s.io/kubelet => k8s.io/kubelet v0.27.6

	// Need replacements for all the k8s subsidiary projects that are pulled in indirectly because
	// the kubernets repo pulls them in via a replacement to its own vendored copies, which doesn't work for
	// transient imports.
	k8s.io/kubernetes => k8s.io/kubernetes v1.27.6
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.27.6
	k8s.io/metrics => k8s.io/metrics v0.27.6
	k8s.io/mount-utils => k8s.io/mount-utils v0.27.6
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.27.6
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.27.6
)
