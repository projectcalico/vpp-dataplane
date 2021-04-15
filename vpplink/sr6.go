package vpplink

import (
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

func (v *VppLink) ListSRv6Policies() (list []*types.SrPolicy, err error) {

	return nil, err
}

func (v *VppLink) AddSRv6Policy(policy *types.SrPolicy) (err error) {

	return err
}

func (v *VppLink) DelSRv6Policy(policy *types.SrPolicy) (err error) {

	return err
}

func (v *VppLink) ListSRv6Localsid() (list []*types.SrLocalsid, err error) {

	return nil, err
}

func (v *VppLink) AddSRv6Localsid(localSid *types.SrLocalsid) (err error) {

	return err
}

func (v *VppLink) DelSRv6Localsid(localSid *types.SrLocalsid) (err error) {

	return err
}
