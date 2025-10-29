module github.com/projectcalico/vpp-dataplane/v3

go 1.24.9

require (
	github.com/calico-vpp/vpplink v0.1.0
	github.com/census-instrumentation/opencensus-proto v0.4.1
	github.com/containernetworking/plugins v1.6.2
	github.com/google/gopacket v1.1.19
	github.com/inconshreveable/mousetrap v1.1.0
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.4.0
	github.com/lunixbochs/struc v0.0.0-20241101090106-8d528fa2c543 // indirect
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.38.0
	github.com/orijtech/prometheus-go-metrics-exporter v0.0.6
	github.com/osrg/gobgp/v3 v3.35.0
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/api v0.0.0-20251022175904-f2ab03771208 // v3.31.0
	github.com/projectcalico/calico v0.0.0-20251021213802-b1f3c43f8437 // v3.31.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/yookoala/realpath v1.0.0
	go.fd.io/govpp v0.11.0
	go.fd.io/govpp/extras v0.1.0
	golang.org/x/net v0.46.0
	golang.org/x/sys v0.37.0
	google.golang.org/grpc v1.72.2
	google.golang.org/protobuf v1.36.7
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	k8s.io/api v0.33.5
	k8s.io/apimachinery v0.33.5
	k8s.io/client-go v0.33.5
	k8s.io/utils v0.0.0-20241210054802-24370beab758
	sigs.k8s.io/controller-runtime v0.20.4
	sigs.k8s.io/yaml v1.6.0 // indirect
)

require (
	github.com/bennyscetbun/jsongo v1.1.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/evanphx/json-patch/v5 v5.9.11 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic-models v0.6.9 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/k-sone/critbitgo v1.4.0 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/projectcalico/calico/lib/std v0.0.0-00010101000000-000000000000 // indirect
	github.com/projectcalico/go-json v0.0.0-20161128004156-6219dc7339ba // indirect
	github.com/projectcalico/go-yaml-wrapper v0.0.0-20191112210931-090425220c54 // indirect
	github.com/prometheus/client_golang v1.23.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.9.2 // indirect
	github.com/spf13/pflag v1.0.7 // indirect
	github.com/spf13/viper v1.20.1 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/etcd/api/v3 v3.6.4 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.6.4 // indirect
	go.etcd.io/etcd/client/v3 v3.6.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/oauth2 v0.32.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250721164621-a45f3dfb1074 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250811230008-5f3141c8851a // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v9 v9.31.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.33.5 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250318190949-c8a335a9a2ff // indirect
	sigs.k8s.io/json v0.0.0-20241014173422-cfa47c3a1cc8 // indirect
	sigs.k8s.io/network-policy-api v0.1.5 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.6.0 // indirect
)

// We match the Calico/VPP version to a given Calico version.
// In order to upgrade proceed as follows
//  - Get the appropriate commit hash for the new versions in both
//     * https://github.com/projectcalico/calico
//     * https://github.com/projectcalico/api
//  - `go get github.com/projectcalico/calico@<commit hash>`
//  - `go get github.com/projectcalico/api@<commit hash>`
//  - This will change the go.mod (this file) & go.sum with
//    `github.com/projectcalico/calico v1.11.0-cni-plugin.0.{SOMEDATE}-{COMMITHASH}`
//    `github.com/projectcalico/api v1.11.0-cni-plugin.0.{SOMEDATE}-{COMMITHASH}`
//  - Edit go.mod (this file) version string to make it `v0.0.0-{SOMEDATE}-{COMMITHASH}`
//  - Add comments e.g. `// v3.30.0` to make the commit hash explicit
//  - Update the `replace ()` section at the bootom of go.mod
//    with the replacement found in github.com/projectcalico/calico/go.mod
//    (those for `google.golang.org/grpc` and `k8s.io/*` in the main section)
//  - upgrade the calico self-references replacements :
//     * github.com/projectcalico/calico/lib/httpmachinery => github.com/projectcalico/calico/lib/httpmachinery v0.0.0-{SOMEDATE}-{COMMITHASH}
//     * github.com/projectcalico/calico/lib/std => github.com/projectcalico/calico/lib/std v0.0.0-{SOMEDATE}-{COMMITHASH}
//
//  - Run `go mod tidy

replace (
	github.com/projectcalico/calico/lib/httpmachinery => github.com/projectcalico/calico/lib/httpmachinery v0.0.0-20251021213802-b1f3c43f8437 // v3.31.0
	github.com/projectcalico/calico/lib/std => github.com/projectcalico/calico/lib/std v0.0.0-20251021213802-b1f3c43f8437 // v3.31.0

	// Newer versions set the file mode on logs to 0600, which breaks a lot of our tests.
	gopkg.in/natefinch/lumberjack.v2 => gopkg.in/natefinch/lumberjack.v2 v2.0.0

	// Need replacements for all the k8s subsidiary projects that are pulled in indirectly because
	// the kubernets repo pulls them in via a replacement to its own vendored copies, which doesn't work for
	// transient imports.
	k8s.io/api => k8s.io/api v0.33.5
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.33.5
	k8s.io/apimachinery => k8s.io/apimachinery v0.33.5
	k8s.io/apiserver => k8s.io/apiserver v0.33.5
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.33.5
	k8s.io/client-go => k8s.io/client-go v0.33.5
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.33.5
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.33.5
	k8s.io/code-generator => k8s.io/code-generator v0.33.5
	k8s.io/component-base => k8s.io/component-base v0.33.5
	k8s.io/component-helpers => k8s.io/component-helpers v0.33.5
	k8s.io/controller-manager => k8s.io/controller-manager v0.33.5
	k8s.io/cri-api => k8s.io/cri-api v0.33.5
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.33.5
	k8s.io/endpointslice => k8s.io/endpointslice v0.33.5
	k8s.io/externaljwt => k8s.io/externaljwt v0.33.5
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.33.5
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.33.5
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.33.5
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.33.5
	k8s.io/kubectl => k8s.io/kubectl v0.33.5
	k8s.io/kubelet => k8s.io/kubelet v0.33.5
	k8s.io/metrics => k8s.io/metrics v0.33.5
	k8s.io/mount-utils => k8s.io/mount-utils v0.33.5
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.33.5
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.33.5
)
