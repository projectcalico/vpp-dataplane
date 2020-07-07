module github.com/projectcalico/vpp-dataplane

go 1.12

require (
	git.fd.io/govpp.git v0.3.4
	github.com/lunixbochs/struc v0.0.0-20190916212049-a5c72983bc42
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/containernetworking/plugins v0.8.2
	github.com/coreos/etcd v3.3.17+incompatible // indirect
	github.com/dgryski/go-farm v0.0.0-20191112170834-c2139c5d712b // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/gophercloud/gophercloud v0.6.0 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/osrg/gobgp v2.0.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/libcalico-go v1.7.3
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/viper v1.5.0 // indirect
	github.com/vishvananda/netlink v1.0.1-0.20191217171528-ed8931371a80
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/sys v0.0.0-20190826190057-c7b8b68b1456
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/grpc v1.24.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	k8s.io/api v0.0.0-20191114100040-7a2cb0978c84
	k8s.io/apimachinery v0.0.0-20191114135336-bcf004c497a4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/utils v0.0.0-20191114181534-f635c9d740df // indirect
)

replace github.com/projectcalico/libcalico-go v1.7.3 => github.com/projectcalico/libcalico-go v1.7.2-0.20191112223013-362a04d5e109

replace github.com/osrg/gobgp v2.0.0+incompatible => github.com/osrg/gobgp v0.0.0-20191101114856-a42a1a5f6bf0

replace github.com/lunixbochs/struc => github.com/sknat/struc v0.0.0-20200617164704-98063b5c2257
