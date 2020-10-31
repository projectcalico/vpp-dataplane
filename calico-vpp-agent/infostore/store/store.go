package store

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/infostore"
	"github.com/sirupsen/logrus"
)

type info struct {
	log *logrus.Entry
	sync.Mutex
	// The key is a combination of pod's namespace and pod's name
	store map[string]*infostore.Record
}

var _ infostore.Manager = &info{}

func (i *info) AddPodInfo(r *infostore.Record) error {
	i.Lock()
	defer i.Unlock()
	if _, ok := i.store[r.Namespace+r.Name]; ok {
		i.log.Warnf("pod %s/%s is already in the store", r.Namespace, r.Name)
	}
	i.store[r.Namespace+r.Name] = r

	return nil
}

func (i *info) RemovePodInfo(interfaceName string) error {
	i.Lock()
	defer i.Unlock()
	found := false
	key := ""
	for _, v := range i.store {
		if strings.Compare(v.InterfaceName, interfaceName) == 0 {
			found = true
			key = v.Namespace + v.Name
			break
		}
	}
	if !found {
		return fmt.Errorf("pod with interface name %s is not found in the store", interfaceName)
	}
	if _, ok := i.store[key]; !ok {
		i.log.Warnf("pod with the key %s is not found in the store", key)
	}
	delete(i.store, key)

	return nil
}
