package grpcsrv

import (
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	pb "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/proto"
)

// Manager defines methods manage pod information store
type Manager interface {
	AddPodInfo(string, *cni.LocalPodSpec, *pb.WorkloadIDs) error
	RemovePodInfo()
}
