package vpplink

import (
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/sr"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/sr_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) SetEncapSource(addr net.IP) error {
	client := sr.NewServiceClient(v.GetConnection())

	_, err := client.SrSetEncapSource(v.GetContext(), &sr.SrSetEncapSource{
		EncapsSource: types.ToVppIP6Address(addr),
	})
	if err != nil {
		return fmt.Errorf("setEncapSource failed: %w", err)
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
		// srpolicy.Srv6SidListFromVPP(response.SidLists)
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

	if len(policy.SidLists) == 0 {
		return fmt.Errorf("failed to add SRv6Policy: policy has no SID lists")
	}
	// Zero BSID would silently target the all-zero entry on subsequent SrPolicyMod calls.
	if (policy.Bsid == ip_types.IP6Address{}) {
		return fmt.Errorf("failed to add SRv6Policy: BSID is unset (zero address)")
	}

	// sr_policy_add takes one list; subsequent lists go via sr_policy_mod ADD.
	// Per-list weight is wire-encoded twice (top-level + nested); set both.
	first := policy.SidLists[0]
	total := len(policy.SidLists)
	if _, err := client.SrPolicyAdd(v.GetContext(), &sr.SrPolicyAdd{
		BsidAddr: policy.Bsid,
		Weight:   first.Weight,
		IsEncap:  policy.IsEncap,
		IsSpray:  policy.IsSpray,
		FibTable: policy.FibTable,
		Sids: sr.Srv6SidList{
			NumSids: first.NumSids,
			Weight:  first.Weight,
			Sids:    first.Sids,
		},
	}); err != nil {
		return fmt.Errorf("failed to add SRv6Policy: %w", err)
	}

	for i, sl := range policy.SidLists[1:] {
		listIdx := i + 2
		if _, err := client.SrPolicyMod(v.GetContext(), &sr.SrPolicyMod{
			BsidAddr:  policy.Bsid,
			FibTable:  policy.FibTable,
			Operation: sr_types.SR_POLICY_OP_API_ADD,
			Weight:    sl.Weight,
			Sids: sr.Srv6SidList{
				NumSids: sl.NumSids,
				Weight:  sl.Weight,
				Sids:    sl.Sids,
			},
		}); err != nil {
			if _, delErr := client.SrPolicyDel(v.GetContext(), &sr.SrPolicyDel{
				BsidAddr: policy.Bsid,
			}); delErr != nil {
				return fmt.Errorf("failed to append SID list %d/%d to SRv6Policy: %w; additionally failed to roll back SRv6Policy: %w", listIdx, total, err, delErr)
			}
			return fmt.Errorf("failed to append SID list %d/%d to SRv6Policy: %w; rolled back by deleting the SRv6Policy", listIdx, total, err)
		}
	}
	return nil
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
		return fmt.Errorf("delete SRv6Localsid failed: %w", err)
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
