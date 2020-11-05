package server

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore/proto"
	pbapi "github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Info interface exposes methods to controller the info store's grpc server
type Info interface {
	Start()
	Stop()
}

var _ Info = &infoSrv{}

type infoSrv struct {
	gSrv     *grpc.Server
	conn     net.Listener
	sockAddr string
	store    infostore.Manager
	log      *logrus.Entry
}

func (i *infoSrv) Start() {
	i.log.Infof("Starting InfoStore's gRPC on %s", i.conn.Addr().String())
	go i.gSrv.Serve(i.conn)

}
func (i *infoSrv) Stop() {
	i.gSrv.GracefulStop()
	syscall.Unlink(i.sockAddr)
}

func (i *infoSrv) Get(ctx context.Context, req *proto.PodInfoReq) (*proto.PodInfoRepl, error) {
	r, err := i.store.GetPodInfo(req.PodId, req.Namespace)
	if err != nil {
		return &proto.PodInfoRepl{
			PodInfo: nil,
			// TODO, maybe define error codes?
			Err:       -1,
			ErrDetail: err.Error(),
		}, err
	}
	// Pod can carry multiple IPs for different address families, selecting ipv6 ip and if it does not exist, returning error
	found := false
	var addr net.IP
	for _, a := range r.IPs {
		if net.IP(a).To16() != nil {
			copy(addr, a)
			found = true
			break
		}
	}
	if !found {
		return &proto.PodInfoRepl{
			PodInfo:   nil,
			Err:       -2,
			ErrDetail: "pod does not have a valid ipv6 address",
		}, err
	}

	return &proto.PodInfoRepl{
		PodInfo: &pbapi.PodInfo{
			TableId:  r.TableID,
			PortName: r.InterfaceName,
			PodAddr: []*pbapi.Address{
				{
					Addr:    addr,
					MaskLen: 128,
					IsIpv6:  true,
				},
			},
		},
		Err:       0,
		ErrDetail: "",
	}, nil
}

// NewInfoServer returns a new instance of the info store grpc server
func NewInfoServer(store infostore.Manager, sockAddr string, log *logrus.Entry) (Info, error) {
	// Initialize gRPC server
	conn, err := net.Listen("unix", sockAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to setup gRPC listener with with error: %+v", err)
	}
	gSrv := grpc.NewServer([]grpc.ServerOption{}...)
	i := &infoSrv{
		gSrv:     gSrv,
		store:    store,
		sockAddr: sockAddr,
		log:      log,
		conn:     conn,
	}
	pbapi.RegisterPodInfoSvcServer(gSrv, i)

	return i, nil
}
