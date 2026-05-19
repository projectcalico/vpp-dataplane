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
	// sr_policy_mod accepts an SR Policy keyed by either bsid_addr or a
	// non-zero sr_policy_index; this code path only sets bsid_addr, so
	// reject a zero / unset BSID up-front. Otherwise an SR Policy that
	// reached AddSRv6Policy without a Binding SID sub-TLV decoded into it
	// would silently target the all-zero-BSID entry on later SrPolicyMod
	// calls.
	if (policy.Bsid == ip_types.IP6Address{}) {
		return fmt.Errorf("failed to add SRv6Policy: BSID is unset (zero address)")
	}

	// VPP's sr_policy_add accepts a single Segment List, so the first one is
	// installed via SrPolicyAdd and any additional lists are appended one at
	// a time with SrPolicyMod{Operation: SR_POLICY_OP_API_ADD}. This keeps
	// the RFC 9256 notion of multiple weighted Segment Lists per SR Policy
	// (ECMP / fallback candidates) intact rather than collapsing them into a
	// single strict chain.
	//
	// The "weight" field appears twice on the wire: once at the top level
	// (sr_policy_add.weight, documented as "weight of the sid list") and
	// once nested inside Sids (vl_api_srv6_sid_list_t.weight). VPP's
	// sr_policy_add_fn implementation reads the top-level field as the
	// authoritative per-SID-list weight; the nested copy is set to the same
	// value so the on-wire srv6_sid_list_t round-trips correctly (the
	// generated marshaller emits both). SrPolicyMod below behaves the same.
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
		listIdx := i + 2 // 1-based, accounting for the SrPolicyAdd above
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
