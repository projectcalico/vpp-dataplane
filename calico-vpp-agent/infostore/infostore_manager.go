package infostore

import "net"

// Manager defines methods manage pod information store
type Manager interface {
	AddPodInfo(*Record) error
	RemovePodInfo(string) error
}

// Record defines the structure of the information record stored in the store
type Record struct {
	Name          string
	Namespace     string
	InterfaceName string
	TableID       int32
	IPs           []net.IP
}
