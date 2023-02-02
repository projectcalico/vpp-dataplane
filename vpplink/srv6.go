package vpplink

import (
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/sr"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) SetEncapSource(addr net.IP) error {
	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrSetEncapSource(v.GetContext(), &sr.SrSetEncapSource{
		EncapsSource: types.ToVppIP6Address(addr),
	})
	if err != nil {
		return fmt.Errorf("SetEncapSource failed: %w", err)
	}
	return err
}

func (v *VppLink) ListSRv6Policies() (list []*types.SrPolicy, err error) {
	client := sr.NewServiceClient(v.GetConnection())

	stream, err := client.SrPoliciesDump(v.GetContext(), &sr.SrPoliciesDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump SR policies: %w", err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump SR policies: %w", err)
		}
		srpolicy := &types.SrPolicy{}
		srpolicy.FromVPP(response)
		//srpolicy.Srv6SidListFromVPP(response.SidLists)
		list = append(list, srpolicy)
	}
	return list, err
}

func (v *VppLink) AddModSRv6Policy(policy *types.SrPolicy) (err error) {
	list, err := v.ListSRv6Policies()
	isAlreadyDefined := false
	if err != nil {
		return fmt.Errorf("error AddModSRv6Policy: %w", err)
	}
	for _, registeredPolicy := range list {
		if policy.Bsid == registeredPolicy.Bsid {
			isAlreadyDefined = true
			break
		}
	}

	if isAlreadyDefined {
		errDel := v.DelSRv6Policy(policy)
		if errDel != nil {
			return errors.Wrapf(errDel, "error AddModSRv6Policy")
		}
	}

	return v.AddSRv6Policy(policy)

}

func (v *VppLink) AddSRv6Policy(policy *types.SrPolicy) error {
	client := sr.NewServiceClient(v.GetConnection())

	// supporting only one SID list here -> multiple weighted paths for workload balance not supported
	// This means that lso IsSpray setting is useless as it switches between default weighted path mode
	// and spray mode(=replicate-traffic-and-multicast-to-all-paths)
	sidlist := policy.SidLists[0]

	_, err := client.SrPolicyAdd(v.GetContext(), &sr.SrPolicyAdd{
		BsidAddr: policy.Bsid,
		IsEncap:  policy.IsEncap,
		IsSpray:  policy.IsSpray,
		FibTable: policy.FibTable,
		Sids: sr.Srv6SidList{
			NumSids: sidlist.NumSids,
			Weight:  sidlist.Weight,
			Sids:    sidlist.Sids,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add SRv6Policy: %w", err)
	}
	return err
}

func (v *VppLink) DelSRv6Policy(policy *types.SrPolicy) error {
	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrPolicyDel(v.GetContext(), &sr.SrPolicyDel{
		BsidAddr: policy.Bsid,
	})
	if err != nil {
		return fmt.Errorf("failed to delete SRv6Policy: %w", err)
	}

	return err
}

func (v *VppLink) ListSRv6Localsid() (list []*types.SrLocalsid, err error) {
	client := sr.NewServiceClient(v.GetConnection())

	stream, err := client.SrLocalsidsDump(v.GetContext(), &sr.SrLocalsidsDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump SR localsids: %w", err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump SR localsids: %w", err)
		}
		list = append(list, &types.SrLocalsid{
			Localsid:  response.Addr,
			EndPsp:    response.EndPsp,
			Behavior:  types.FromVppSrBehavior(response.Behavior),
			SwIfIndex: interface_types.InterfaceIndex(response.XconnectIfaceOrVrfTable),
			VlanIndex: response.VlanIndex,
			FibTable:  response.FibTable,
			NhAddr:    response.XconnectNhAddr,
		})
	}
	return list, err
}

func (v *VppLink) AddSRv6Localsid(localSid *types.SrLocalsid) error {

	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrLocalsidAddDel(v.GetContext(), &sr.SrLocalsidAddDel{
		IsDel:     false,
		Localsid:  localSid.Localsid,
		EndPsp:    localSid.EndPsp,
		Behavior:  types.ToVppSrBehavior(localSid.Behavior),
		SwIfIndex: localSid.SwIfIndex,
		VlanIndex: localSid.VlanIndex,
		FibTable:  localSid.FibTable,
		NhAddr:    localSid.NhAddr,
	})
	if err != nil {
		return fmt.Errorf("failed to add SRv6Localsid: %w", err)
	}

	return err
}

func (v *VppLink) DelSRv6Localsid(localSid *types.SrLocalsid) error {
	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrLocalsidAddDel(v.GetContext(), &sr.SrLocalsidAddDel{
		IsDel:     true,
		Localsid:  localSid.Localsid,
		EndPsp:    localSid.EndPsp,
		Behavior:  types.ToVppSrBehavior(localSid.Behavior),
		SwIfIndex: localSid.SwIfIndex,
		VlanIndex: localSid.VlanIndex,
		FibTable:  localSid.FibTable,
		NhAddr:    localSid.NhAddr,
	})
	if err != nil {
		return fmt.Errorf("Delete SRv6Localsid failed: %w", err)
	}
	return err
}

func (v *VppLink) DelSRv6Steering(steer *types.SrSteer) error {
	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrSteeringAddDel(v.GetContext(), &sr.SrSteeringAddDel{
		IsDel:       true,
		BsidAddr:    steer.Bsid,
		TableID:     steer.FibTable,
		Prefix:      steer.Prefix,
		SwIfIndex:   interface_types.InterfaceIndex(steer.SwIfIndex),
		TrafficType: types.ToVppSrSteerTrafficType(steer.TrafficType),
	})
	if err != nil {
		return fmt.Errorf("failed to delete SRv6Steering: %w", err)
	}
	return err
}

func (v *VppLink) AddSRv6Steering(steer *types.SrSteer) error {
	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrSteeringAddDel(v.GetContext(), &sr.SrSteeringAddDel{
		IsDel:       false,
		BsidAddr:    steer.Bsid,
		TableID:     steer.FibTable,
		Prefix:      steer.Prefix,
		SwIfIndex:   interface_types.InterfaceIndex(steer.SwIfIndex),
		TrafficType: types.ToVppSrSteerTrafficType(steer.TrafficType),
	})
	if err != nil {
		return fmt.Errorf("failed to add SRv6Steering: %w", err)
	}
	return err
}

func (v *VppLink) ListSRv6Steering() (list []*types.SrSteer, err error) {
	client := sr.NewServiceClient(v.GetConnection())

	stream, err := client.SrSteeringPolDump(v.GetContext(), &sr.SrSteeringPolDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump SR steering: %w", err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump SR steering: %w", err)
		}
		list = append(list, &types.SrSteer{
			TrafficType: types.FromVppSrSteerTrafficType(response.TrafficType),
			FibTable:    response.FibTable,
			Prefix:      response.Prefix,
			SwIfIndex:   uint32(response.SwIfIndex),
			Bsid:        response.Bsid,
		})
	}
	return list, err
}
