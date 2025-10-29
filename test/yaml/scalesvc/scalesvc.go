package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	t                   tomb.Tomb
	clusterConfig       *restclient.Config
	NServices           int = 10000
	NWorkers            int = 64
	TargetAddr          string
	createdServiceCount uint32 = 0
)

func incMaybePrint() {
	if atomic.AddUint32(&createdServiceCount, uint32(1))%100 == 0 {
		log.Infof("%d/%d", createdServiceCount, NServices)
	}
}

func parallel(val int, modul int) func() error {
	return func() error {
		client, err := kubernetes.NewForConfig(clusterConfig)
		if err != nil {
			panic(err.Error())
		}
		corev1 := client.CoreV1()
		discoveryv1client := client.DiscoveryV1()

		for i := 1; i <= NServices; i++ {
			if i%modul != val {
				continue
			}
			service := v1.Service{
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{{
						Port:     80,
						Protocol: "TCP",
					}},
					ClusterIP: "",
				},
			}
			service.Name = fmt.Sprintf("nginx-service-%d", i)
			service.Namespace = "backs"
			_, err := corev1.Services("backs").Create(context.Background(), &service, metav1.CreateOptions{})
			if err != nil {
				log.Errorf("err: %v ", err)
			}
			protocol := v1.ProtocolTCP
			port := int32(80)
			endpointSlice := discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("nginx-service-%d", i),
					Namespace: "backs",
					Labels: map[string]string{
						discoveryv1.LabelServiceName: fmt.Sprintf("nginx-service-%d", i),
					},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{{
					Addresses: []string{TargetAddr},
				}},
				Ports: []discoveryv1.EndpointPort{{
					Port:     &port,
					Protocol: &protocol,
				}},
			}

			_, err = discoveryv1client.EndpointSlices("backs").Create(context.Background(), &endpointSlice, metav1.CreateOptions{})
			if err != nil {
				log.Errorf("err: %v ", err)
			}
			incMaybePrint()
		}
		return nil
	}
}

func main() {
	var kubeconfig *string
	var err error
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	nServices := flag.Int("services", 100, "Number of service IPs to create")
	nWorkers := flag.Int("t", 64, "Number of parallel routines")
	targetAddr := flag.String("ip", "", "Target ip address of services")
	flag.Parse()
	NServices = *nServices
	NWorkers = *nWorkers
	TargetAddr = *targetAddr

	if TargetAddr == "" {
		log.Panic("No Target Addr provided")
	}

	// use the current context in kubeconfig
	clusterConfig, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	for i := 0; i < NWorkers; i++ {
		t.Go(parallel(i, NWorkers))
	}
	<-t.Dying()
}
