package vpplink

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/sr"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) SetEncapSource(addr net.IP) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &sr.SrSetEncapSource{
		EncapsSource: types.ToVppIP6Address(addr),
	}
	response := &sr.SrSetEncapSourceReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "SetEncapSource failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("SetEncapSource failed with retval %d", response.Retval)
	}
	return err
}

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
		srpolicy := &types.SrPolicy{}
		srpolicy.FromVPP(response)
		//srpolicy.Srv6SidListFromVPP(response.SidLists)
		list = append(list, srpolicy)

	}
	return list, err
}

func (v *VppLink) AddSRv6Policy(policy *types.SrPolicy) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &sr.SrPolicyAddReply{}
	sidlist := policy.SidLists[0]
	request := &sr.SrPolicyAdd{
		BsidAddr: policy.Bsid,
		IsEncap:  policy.IsEncap,
		IsSpray:  policy.IsSpray,
		FibTable: policy.FibTable,
		Sids: sr.Srv6SidList{
			NumSids: sidlist.NumSids,
			Weight:  sidlist.Weight,
			Sids:    sidlist.Sids,
		},
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

func (v *VppLink) DelSRv6Steering(steer *types.SrSteer) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &sr.SrSteeringAddDelReply{}
	request := &sr.SrSteeringAddDel{
		IsDel:       true,
		BsidAddr:    steer.Bsid,
		TableID:     steer.FibTable,
		Prefix:      steer.Prefix,
		SwIfIndex:   interface_types.InterfaceIndex(steer.SwIfIndex),
		TrafficType: steer.TrafficType,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Add DelSRv6Steering failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add DelSRv6Steering failed with retval %d", response.Retval)
	}
	return err
}

func (v *VppLink) AddSRv6Steering(steer *types.SrSteer) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	response := &sr.SrSteeringAddDelReply{}
	request := &sr.SrSteeringAddDel{
		IsDel:       false,
		BsidAddr:    steer.Bsid,
		TableID:     steer.FibTable,
		Prefix:      steer.Prefix,
		SwIfIndex:   interface_types.InterfaceIndex(steer.SwIfIndex),
		TrafficType: steer.TrafficType,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Add AddSRv6Steering failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Add AddSRv6Steering failed with retval %d", response.Retval)
	}
	return err
}

func (v *VppLink) ListSRv6Steering() (list []*types.SrSteer, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	request := &sr.SrSteeringPolDump{}
	stream := v.ch.SendMultiRequest(request)
	for {
		response := &sr.SrSteeringPolDetails{}
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			return nil, errors.Wrapf(err, "error listing SRv6 Steering")
		}
		if stop {
			break
		}
		list = append(list, &types.SrSteer{
			TrafficType: response.TrafficType,
			FibTable:    response.FibTable,
			Prefix:      response.Prefix,
			SwIfIndex:   uint32(response.SwIfIndex),
			Bsid:        response.Bsid,
		})
	}
	return list, err
}
