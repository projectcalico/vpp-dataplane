package infostore

import "net"

// Manager defines methods manage pod information store
type Manager interface {
	// AddPodInfo used by CNI server to add pod's related information to the store
	AddPodInfo(*Record) error
	// RemovePodInfo used by CNI server to remove pod's related information from thestore
	RemovePodInfo(interfaceName string) error
	// GetPodInfo returns a ifnromation record for a specific pod namespace / pod name pair
	// in case of any failure error is returned to the caller
	GetPodInfo(podName string, podNamespace string) (*Record, error)
}

// Record defines the structure of the information record stored in the store
type Record struct {
	Name          string
	Namespace     string
	InterfaceName string
	TableID       int32
	IPs           []net.IP
}
