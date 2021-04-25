package vpplink

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/sr"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) ListSRv6Policies() (list []*types.SrPolicy, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &sr.SrPoliciesDump{}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &sr.SrPoliciesDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error SRv6Policies")
		}
		if stop {
			break
		}
		sidLists := make([]types.Srv6SidList, response.NumSidLists)
		for i, sidlist := range response.SidLists {
			sidLists[i] = types.Srv6SidList{
				NumSids: sidlist.NumSids,
				Weight:  sidlist.Weight,
				Sids:    sidlist.Sids,
			}
		}
		list = append(list, &types.SrPolicy{
			Bsid:        response.Bsid,
			IsSpray:     response.IsSpray,
			IsEncap:     response.IsEncap,
			FibTable:    response.FibTable,
			NumSidLists: response.NumSidLists,
			SidLists:    sidLists,
		})
	}
	return list, err
}

func (v *VppLink) AddSRv6Policy(policy *types.SrPolicy) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &sr.SrPolicyAddReply{}
	request := &sr.SrPolicyAdd{
		BsidAddr: policy.Bsid,
		IsEncap:  policy.IsEncap,
		IsSpray:  policy.IsSpray,
		FibTable: policy.FibTable,
		//Sids:     policy.SidLists,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Add SRv6Policy failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add SRv6Policy failed with retval %d", response.Retval)
	}
	return err
}

func (v *VppLink) DelSRv6Policy(policy *types.SrPolicy) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &sr.SrPolicyDelReply{}
	request := &sr.SrPolicyDel{
		BsidAddr: policy.Bsid,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Del SRv6Policy failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Del SRv6Policy failed with retval %d", response.Retval)
	}

	return err
}

func (v *VppLink) ListSRv6Localsid() (list []*types.SrLocalsid, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &sr.SrLocalsidsDump{}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &sr.SrLocalsidsDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing IPIP tunnels")
		}
		if stop {
			break
		}
		list = append(list, &types.SrLocalsid{
			Localsid:  response.Addr,
			EndPsp:    response.EndPsp,
			Behavior:  response.Behavior,
			SwIfIndex: interface_types.InterfaceIndex(response.XconnectIfaceOrVrfTable),
			VlanIndex: response.VlanIndex,
			FibTable:  response.FibTable,
			NhAddr:    response.XconnectNhAddr,
		})
	}

	return list, err
}

func (v *VppLink) AddSRv6Localsid(localSid *types.SrLocalsid) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &sr.SrLocalsidAddDelReply{}
	request := &sr.SrLocalsidAddDel{
		IsDel:     false,
		Localsid:  localSid.Localsid,
		EndPsp:    localSid.EndPsp,
		Behavior:  localSid.Behavior,
		SwIfIndex: localSid.SwIfIndex,
		VlanIndex: localSid.VlanIndex,
		FibTable:  localSid.FibTable,
		NhAddr:    localSid.NhAddr,
	}
	err_send := v.ch.SendRequest(request).ReceiveReply(response)
	if err_send != nil {
		return errors.Wrap(err_send, "Add SRv6Localsid failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add SRv6Localsid failed with retval %d", response.Retval)
	}

	return err
}

func (v *VppLink) DelSRv6Localsid(localSid *types.SrLocalsid) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &sr.SrLocalsidAddDelReply{}
	request := &sr.SrLocalsidAddDel{
		IsDel:     true,
		Localsid:  localSid.Localsid,
		EndPsp:    localSid.EndPsp,
		Behavior:  localSid.Behavior,
		SwIfIndex: localSid.SwIfIndex,
		VlanIndex: localSid.VlanIndex,
		FibTable:  localSid.FibTable,
		NhAddr:    localSid.NhAddr,
	}
	err_send := v.ch.SendRequest(request).ReceiveReply(response)
	if err_send != nil {
		return errors.Wrap(err_send, "Delete SRv6Localsid failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Delete SRv6Localsid failed with retval %d", response.Retval)
	}
	return err
}
