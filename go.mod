module github.com/projectcalico/vpp-dataplane

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210927044411-385ccc0d8ba9
	github.com/census-instrumentation/opencensus-proto v0.2.1
	github.com/containernetworking/plugins v0.8.5
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.2
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/orijtech/prometheus-go-metrics-exporter v0.0.6
	github.com/osrg/gobgp v0.0.0-20210801043420-9e48a36ed97c
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/api v0.0.0-20220129171738-695e97a25204 // v3.22.0
	github.com/projectcalico/calico v0.0.0-20220128225346-a86e41d021c4 // v3.22.0
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.10.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/vishvananda/netlink v1.1.1-0.20210703095558-21f2c55a7727
	github.com/yookoala/realpath v1.0.0
	golang.org/x/net v0.0.0-20211216030914-fe4d6282115f
	golang.org/x/sys v0.0.0-20210816074244-15123e1e1f71
	google.golang.org/grpc v1.31.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	k8s.io/api v0.22.5
	k8s.io/apimachinery v0.22.5
	k8s.io/client-go v0.22.5
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
)

replace (
	github.com/projectcalico/api => github.com/projectcalico/api v0.0.0-20220129171738-695e97a25204 // v3.22.0

	google.golang.org/grpc => google.golang.org/grpc v1.29.1

	k8s.io/api => k8s.io/api v0.21.8
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.8
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.8
	k8s.io/apiserver => k8s.io/apiserver v0.21.8
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.21.8
	k8s.io/client-go => github.com/projectcalico/k8s-client-go v0.21.9-0.20220104180519-6bd7ec39553f
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.21.8
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.21.8
	k8s.io/code-generator => k8s.io/code-generator v0.21.8
	k8s.io/component-base => k8s.io/component-base v0.21.8
	k8s.io/component-helpers => k8s.io/component-helpers v0.21.8
	k8s.io/controller-manager => k8s.io/controller-manager v0.21.8
	k8s.io/cri-api => k8s.io/cri-api v0.21.8
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.21.8
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.21.8
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.21.8
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.21.8
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.21.8
	k8s.io/kubectl => k8s.io/kubectl v0.21.8
	k8s.io/kubelet => k8s.io/kubelet v0.21.8

	k8s.io/kubernetes => k8s.io/kubernetes v1.21.8
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.21.8
	k8s.io/metrics => k8s.io/metrics v0.21.8
	k8s.io/mount-utils => k8s.io/mount-utils v0.21.8
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.21.8
)
