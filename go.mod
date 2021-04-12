module github.com/projectcalico/vpp-dataplane

go 1.15

require (
	git.fd.io/govpp.git v0.3.6-0.20210202134006-4c1cccf48cd1
	github.com/containernetworking/plugins v0.8.2
	github.com/dgryski/go-farm v0.0.0-20191112170834-c2139c5d712b // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.2
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/osrg/gobgp v0.0.0-20210302053313-5960e8ebd1e3
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/libcalico-go v1.7.2-0.20210305184916-02db57c95742
	github.com/prometheus/common v0.4.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/viper v1.5.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/vishvananda/netlink v1.1.0
	github.com/yookoala/realpath v1.0.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201112073958-5cba982894dd
	google.golang.org/grpc v1.27.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	k8s.io/api v0.19.6
	k8s.io/apimachinery v0.19.6
	k8s.io/client-go v0.19.6
)
