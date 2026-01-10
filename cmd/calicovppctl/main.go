// Copyright (C) 2025 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gookit/color"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

const (
	defaultNamespace     = "calico-vpp-dataplane"
	calicoSystemNS       = "calico-system"
	operatorNamespace    = "tigera-operator"
	defaultPod           = "calico-vpp-node"
	defaultContainerVpp  = "vpp"
	defaultContainerAgt  = "agent"
	defaultCalicoPod     = "calico-node"
	defaultCalicoSvcCont = "calico-node"

	// Command constants
	kubectlCmd  = "kubectl"
	bashCmd     = "bash"
	vppctlPath  = "/usr/bin/vppctl"
	vppSockPath = "/var/run/vpp/cli.sock"
	dockerCmd   = "docker"

	// Command templates
	cmdVppHardInt = "show hardware-interfaces"
	cmdVppShowRun = "show run"
	cmdVppShowErr = "show err"

	// Kubernetes client timeout
	kubeClientTimeout = 15 * time.Second

	// Capture lock file path (inside VPP pod)
	captureLockFile = "/tmp/calicovppctl.lock"

	// Capture server port
	captureServerPort = 9999
)

// StatusResponse represents the status response from the capture server
type StatusResponse struct {
	Status      string `json:"status"`
	CaptureType string `json:"captureType,omitempty"`
	FilePath    string `json:"filePath,omitempty"`
	RemainingMs int64  `json:"remainingMs,omitempty"`
}

// CaptureResponse represents the response from capture operations
type CaptureResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Status   string `json:"status"`
	FilePath string `json:"filePath,omitempty"`
	Error    string `json:"error,omitempty"`
}

// CaptureLockInfo represents the information stored in the lock file
type CaptureLockInfo struct {
	NodeName  string    `json:"node_name"`
	Operation string    `json:"operation"`
	StartedAt time.Time `json:"started_at"`
	Hostname  string    `json:"hostname"`
	BPFActive bool      `json:"bpf_active"`
}

type KubeClient struct {
	clientset *kubernetes.Clientset
	timeout   time.Duration
}

func newKubeClient() (*KubeClient, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	return &KubeClient{clientset: clientset, timeout: kubeClientTimeout}, nil
}

func (k *KubeClient) getAvailableNodeNames() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	nodes, err := k.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var nodeNames []string
	for _, node := range nodes.Items {
		nodeNames = append(nodeNames, node.Name)
	}

	return nodeNames, nil
}

func (k *KubeClient) findNodePod(nodeName, podPrefix, namespace string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	pods, err := k.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return "", err
	}

	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, podPrefix) {
			return pod.Name, nil
		}
	}

	return "", fmt.Errorf("pod with prefix '%s' not found on node '%s'", podPrefix, nodeName)
}

func (k *KubeClient) execInPod(namespace, podName, containerName string, command ...string) (string, error) {
	cmd := exec.Command(kubectlCmd, append([]string{
		"exec",
		"-n", namespace,
		"-c", containerName,
		podName,
		"--",
	}, command...)...)

	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (k *KubeClient) getPodLogs(namespace, podName, containerName string, follow bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	// Create log options
	logOptions := &corev1.PodLogOptions{
		Follow: follow,
	}

	if containerName != "" {
		logOptions.Container = containerName
	}

	// Get the log request
	req := k.clientset.CoreV1().Pods(namespace).GetLogs(podName, logOptions)

	// Execute the request
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get logs for pod %s: %v", podName, err)
	}
	defer podLogs.Close()

	// Read all the logs
	buf := new(strings.Builder)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return "", fmt.Errorf("failed to read logs: %v", err)
	}

	return buf.String(), nil
}

func (k *KubeClient) vppctl(nodeName string, args ...string) (string, error) {
	podName, err := k.findNodePod(nodeName, defaultPod, defaultNamespace)
	if err != nil {
		return "", err
	}

	vppCtlArgs := append([]string{vppctlPath, "-s", vppSockPath}, args...)
	return k.execInPod(defaultNamespace, podName, defaultContainerVpp, vppCtlArgs...)
}

func printColored(colorName, message string) {
	switch colorName {
	case "green":
		color.Green.Println(message)
	case "red":
		color.Red.Println(message)
	case "blue":
		color.Blue.Println(message)
	case "grey":
		color.Gray.Println(message)
	default:
		fmt.Println(message)
	}
}

func printColoredDot(colorName string) {
	switch colorName {
	case "green":
		color.Green.Print(".")
	case "red":
		color.Red.Print(".")
	case "blue":
		color.Blue.Print(".")
	case "grey":
		color.Gray.Print(".")
	default:
		fmt.Print(".")
	}
}

func handleError(err error, message string) {
	if err != nil {
		printColored("red", fmt.Sprintf("%s: %v", message, err))
		os.Exit(1)
	}
}

func validateNodeName(k *KubeClient, nodeName string) (string, error) {
	nodeNames, err := k.getAvailableNodeNames()
	if err != nil {
		return "", err
	}

	if len(nodeNames) == 0 {
		return "", fmt.Errorf("no nodes found. Is cluster running?")
	}

	if nodeName == "" && len(nodeNames) == 1 {
		return nodeNames[0], nil
	}

	for _, n := range nodeNames {
		if n == nodeName {
			return nodeName, nil
		}
	}

	var nodeList strings.Builder
	nodeList.WriteString("\nAvailable nodes:")
	for i, n := range nodeNames {
		nodeList.WriteString(fmt.Sprintf("\n%d. %s", i+1, n))
	}

	return "", fmt.Errorf("node '%s' not found.%s", nodeName, nodeList.String())
}

// writeToFile writes data to a file in the specified directory with a prefix
func writeToFile(exportDir, prefix, file, data string) error {
	f, err := os.Create(filepath.Join(exportDir, prefix+file))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(data)
	return err
}

// CommandSpec defines a command and its output file
type CommandSpec struct {
	cmd  string
	file string
}

// runCommandAndWriteToFile executes a command and writes output to a file
func runCommandAndWriteToFile(exportDir, prefix, command string, args []string, outFile string) {
	cmd := exec.Command(command, args...)
	output, _ := cmd.CombinedOutput()
	_ = writeToFile(exportDir, prefix, outFile, string(output))
	printColoredDot("grey")
}

// runVppctlCommandAndWriteToFile executes a VPP command and writes output to a file
func runVppctlCommandAndWriteToFile(k *KubeClient, exportDir, prefix, node string, cmdSpec CommandSpec) {
	output, _ := k.vppctl(node, strings.Split(cmdSpec.cmd, " ")...)
	_ = writeToFile(exportDir, prefix, cmdSpec.file, output)
	printColoredDot("grey")
}

// executeVppCommandGroup executes a group of VPP commands on a node and writes outputs to files
func executeVppCommandGroup(k *KubeClient, exportDir, prefix, node string, description string, cmds []CommandSpec) {
	printColored("grey", fmt.Sprintf("%s '%s'", description, node))
	for _, c := range cmds {
		runVppctlCommandAndWriteToFile(k, exportDir, prefix, node, c)
	}
	fmt.Println()
}

func exportData(k *KubeClient, nodeName string) error {
	// Create a temporary directory for the export
	exportDir, err := os.MkdirTemp("", "calico-vpp-export-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %v", err)
	}

	// Create export tar file with the same name as the directory under /tmp
	exportDirName := filepath.Base(exportDir)
	exportTarPath := filepath.Join("/tmp", exportDirName+".tar.gz")

	// Generate a timestamp-based prefix
	prefix := time.Now().Format("20060102-150405") + "-"

	printColored("green", fmt.Sprintf("Exporting to temporary directory %s with prefix %s", exportDir, prefix))

	// Collect Kubernetes data
	printColored("grey", "Logging k8s internals")

	// Collect Kubernetes data using clientset APIs
	err = k.collectKubernetesData(exportDir, prefix)
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to collect some Kubernetes data: %v", err))
	}

	// Get calico-vpp-config
	runCommandAndWriteToFile(exportDir, prefix, kubectlCmd, []string{"-n", "calico-vpp-dataplane", "get", "configmap", "calico-vpp-config", "-o", "yaml"}, "calico-vpp-config.configmap.yaml")

	// Get operator logs
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	operatorPods, err := k.clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{})
	cancel()

	if err == nil && len(operatorPods.Items) > 0 {
		operatorPodName := operatorPods.Items[0].Name
		logs, _ := k.getPodLogs(operatorNamespace, operatorPodName, "", false)
		_ = writeToFile(exportDir, prefix, "operator.log", logs)
	}
	printColoredDot("grey")
	fmt.Println()

	// Collect per-node data
	nodeNames, _ := k.getAvailableNodeNames()

	// Filter nodes if specific node is provided
	if nodeName != "" {
		// Only process the specified node
		nodeNames = []string{nodeName}
	}

	for _, node := range nodeNames {
		// Get VPP stats
		vppStatCmds := []CommandSpec{
			{cmdVppHardInt, node + ".hardware-interfaces"},
			{cmdVppShowRun, node + ".show-run"},
			{cmdVppShowErr, node + ".show-err"},
			{"show log", node + ".show-log"},
			{"show buffers", node + ".show-buffers"},
			{"show int", node + ".show-int"},
			{"show int rx", node + ".show-int-rx"},
			{"show tun", node + ".show-tun"},
		}
		executeVppCommandGroup(k, exportDir, prefix, node, "Dumping node stats", vppStatCmds)

		// Get Calico logs
		calicoPodName, err := k.findNodePod(node, defaultCalicoPod, calicoSystemNS)
		if err == nil {
			printColored("grey", fmt.Sprintf("Dumping node '%s' calico logs", node))
			// Describe calico-node pod
			runCommandAndWriteToFile(exportDir, prefix, kubectlCmd, []string{"-n", calicoSystemNS, "describe", "pod/" + calicoPodName}, node+".describe-calico-node-pod")

			// Get calico-node logs
			logs, _ := k.getPodLogs(calicoSystemNS, calicoPodName, defaultCalicoSvcCont, false)
			_ = writeToFile(exportDir, prefix, node+".calico-node.log", logs)
			printColoredDot("grey")
		}
		fmt.Println()

		// Get VPP logs
		printColored("grey", fmt.Sprintf("Dumping node '%s' vpp logs", node))
		vppPodName, err := k.findNodePod(node, defaultPod, defaultNamespace)
		if err == nil {
			// Describe VPP pod
			runCommandAndWriteToFile(exportDir, prefix, kubectlCmd, []string{"-n", defaultNamespace, "describe", "pod/" + vppPodName}, node+".describe-vpp-pod")

			// Get VPP container logs
			vppLogs, _ := k.getPodLogs(defaultNamespace, vppPodName, defaultContainerVpp, false)
			_ = writeToFile(exportDir, prefix, node+".vpp.log", vppLogs)
			printColoredDot("grey")

			// Get Agent container logs
			agentLogs, _ := k.getPodLogs(defaultNamespace, vppPodName, defaultContainerAgt, false)
			_ = writeToFile(exportDir, prefix, node+".agent.log", agentLogs)
			printColoredDot("grey")
		}
		fmt.Println()

		// Get CNAT state
		cnatCmds := []CommandSpec{
			{"show cnat client", node + ".show-cnat-client"},
			{"show cnat translation", node + ".show-cnat-translation"},
			{"show cnat session verbose", node + ".show-cnat-session"},
			{"show cnat timestamp", node + ".show-cnat-timestamp"},
			{"show cnat snat", node + ".show-cnat-snat"},
		}
		executeVppCommandGroup(k, exportDir, prefix, node, "Dumping node state", cnatCmds)

		// Get NPOL policies
		npolCmds := []CommandSpec{
			{"show npol interfaces", node + ".show-npol-interfaces"},
			{"show npol policies verbose", node + ".show-npol-policies"},
			{"show npol rules", node + ".show-npol-rules"},
			{"show npol ipsets", node + ".show-npol-ipsets"},
		}
		executeVppCommandGroup(k, exportDir, prefix, node, "Dumping node policies", npolCmds)
	}

	// Compress the temporary directory
	printColored("grey", "Compressing...")
	err = createTarGz(exportDir, exportTarPath)
	if err != nil {
		return err
	}

	// Remove the contents of the directory since they are already zipped
	printColored("grey", "Cleaning up temporary files...")
	err = os.RemoveAll(exportDir)
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to clean up temporary directory: %v", err))
	}

	printColored("green", fmt.Sprintf("Done exporting to %s", exportTarPath))

	return nil
}

func clearVppStats(k *KubeClient) error {
	nodeNames, err := k.getAvailableNodeNames()
	if err != nil {
		return err
	}

	for _, node := range nodeNames {
		_, _ = k.vppctl(node, "clear", "run")
		_, _ = k.vppctl(node, "clear", "err")
	}

	return nil
}

func printLogs(k *KubeClient, nodeName string, component string, follow bool) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	if component == "" || component == "all" {
		printColored("blue", "----- Felix -----")
		felixPod, err := k.findNodePod(validatedNode, defaultCalicoPod, calicoSystemNS)
		if err == nil {
			logs, _ := getPodLogsFiltered(k, calicoSystemNS, felixPod, "", false,
				func(line string) bool {
					return !strings.Contains(line, "time=")
				})
			fmt.Println(logs)
		}

		printColored("blue", "----- VPP Manager -----")
		vppPod, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
		if err == nil {
			logs, _ := k.getPodLogs(defaultNamespace, vppPod, defaultContainerVpp, false)
			fmt.Println(logs)
		}

		printColored("blue", "----- Calico-VPP agent -----")
		agentPod, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
		if err == nil {
			logs, _ := k.getPodLogs(defaultNamespace, agentPod, defaultContainerAgt, false)
			fmt.Println(logs)
		}

		return nil
	}

	// Specific component logs
	switch component {
	case "vpp":
		printColored("blue", "----- VPP Manager -----")
		vppPod, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
		if err != nil {
			return err
		}
		logs, err := k.getPodLogs(defaultNamespace, vppPod, defaultContainerVpp, follow)
		if err != nil {
			return err
		}
		fmt.Print(logs)

	case "agent":
		printColored("blue", "----- Calico-VPP agent -----")
		agentPod, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
		if err != nil {
			return err
		}
		logs, err := k.getPodLogs(defaultNamespace, agentPod, defaultContainerAgt, follow)
		if err != nil {
			return err
		}
		fmt.Print(logs)

	case "felix":
		printColored("blue", "----- Felix -----")
		felixPod, err := k.findNodePod(validatedNode, defaultCalicoPod, calicoSystemNS)
		if err != nil {
			return err
		}

		// Use filter function to exclude time= entries
		logs, err := getPodLogsFiltered(k, calicoSystemNS, felixPod, "", follow,
			func(line string) bool {
				return !strings.Contains(line, "time=")
			})
		if err != nil {
			return err
		}
		fmt.Print(logs)
	}

	return nil
}

func getShell(k *KubeClient, component, nodeName string) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	podName, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
	if err != nil {
		return err
	}

	var containerName string

	switch component {
	case "vpp":
		containerName = defaultContainerVpp
		printColored("grey", "This shell lives inside the vpp container")
		printColored("grey", "You will find vpp-manager & vpp running")

	case "agent":
		containerName = defaultContainerAgt
		printColored("grey", "This shell lives inside the agent container")
		printColored("grey", "You will find calico-vpp-agent & felix running")

	default:
		return fmt.Errorf("unknown component: %s. Use 'vpp' or 'agent'", component)
	}

	cmd := exec.Command(kubectlCmd, "exec", "-it", "-n", defaultNamespace, "-c", containerName, podName, "--", bashCmd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func printHelp() {
	banner := `   ______      ___               _    ______  ____
  / ____/___ _/ (_)________     | |  / / __ \/ __ \
 / /   / __ ` + "`" + `/ / / ___/ __ \    | | / / /_/ / /_/ /
/ /___/ /_/ / / / /__/ /_/ /    | |/ / ____/ ____/
\____/\__,_/_/_/\___/\____/     |___/_/   /_/
`
	fmt.Print(banner)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println()
	fmt.Println("calicovppctl vppctl [-node NODENAME] [VPP_COMMANDS...]                - Get a vppctl shell or run VPP commands on a specific node")
	fmt.Println("calicovppctl log [-f] [-component vpp|agent|felix] [-node NODENAME]   - Get the logs of vpp (dataplane) or agent (controlplane) or felix daemon")
	fmt.Println("calicovppctl clear                                                    - Clear vpp internal stats")
	fmt.Println("calicovppctl capture clear [-node NODENAME]                           - Clear all active captures and BPF filters (forced cleanup)")
	fmt.Println("calicovppctl capture status [-node NODENAME]                          - Get current capture status via capture server")
	fmt.Println("calicovppctl capture stop [-node NODENAME] [-output FILE]             - Stop capture (if running) and download the capture file")
	fmt.Println("calicovppctl export                                                   - Create an archive with vpp & k8 system state for debugging")
	fmt.Println("calicovppctl exportnode [-node NODENAME]                              - Create an archive with vpp & k8 system state for a specific node")
	fmt.Println("calicovppctl gdb                                                      - Attach gdb to the running vpp on the current machine")
	fmt.Println("calicovppctl sh [-component vpp|agent] [-node NODENAME]               - Get a shell in vpp (dataplane) or agent (controlplane) container")
	fmt.Println("calicovppctl trace [-node NODENAME] [-use-api]                        - Setup VPP packet tracing")
	fmt.Println("      Optional params: [-count N] [-timeout SEC] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl]")
	fmt.Println("      Filter params: [-srcip IP] [-dstip IP] [-srcport PORT] [-dstport PORT] [-protocol tcp|udp|icmp]")
	fmt.Println("calicovppctl pcap [-node NODENAME] [-use-api]                         - Setup VPP PCAP tracing")
	fmt.Println("      Optional params: [-count N] [-timeout SEC] [-interface INTERFACE_NAME|any(default)] [-output FILE.pcap]")
	fmt.Println("      Filter params: [-srcip IP] [-dstip IP] [-srcport PORT] [-dstport PORT] [-protocol tcp|udp|icmp]")
	fmt.Println("calicovppctl dispatch [-node NODENAME] [-use-api]                     - Setup VPP dispatch tracing")
	fmt.Println("      Optional params: [-count N] [-timeout SEC] [-interface phy|af_xdp|af_packet|avf|vmxnet3|virtio|rdma|dpdk|memif|vcl] [-output FILE.pcap]")
	fmt.Println("      Filter params: [-srcip IP] [-dstip IP] [-srcport PORT] [-dstport PORT] [-protocol tcp|udp|icmp]")
	fmt.Println()
	fmt.Println("Note: Use -use-api flag to use HTTP capture server (binary API) instead of vppctl commands")
	fmt.Println()
}

func main() {
	// Define global flags
	var (
		nodeName      = flag.String("node", "", "Node name to operate on")
		component     = flag.String("component", "", "Component to operate on (vpp, agent, felix)")
		follow        = flag.Bool("f", false, "Follow logs (for log command)")
		help          = flag.Bool("help", false, "Show help message")
		count         = flag.Int("count", 1000, "Packet count for trace/pcap/dispatch commands")
		timeout       = flag.Int("timeout", 30, "Timeout in seconds for trace/pcap/dispatch commands (default: 30)")
		interfaceType = flag.String("interface", "", "interface types for trace/dispatch; interface names for pcap. See help for supported types")
		output        = flag.String("output", "", "Output file for pcap/dispatch commands")
		// BPF filter flags
		srcIP    = flag.String("srcip", "", "Source IP address filter (10.0.0.20, 2a04:baba::20, etc.)")
		dstIP    = flag.String("dstip", "", "Destination IP address filter (169.254.0.1, fe80:face::1, etc.)")
		srcPort  = flag.Int("srcport", 0, "Source port filter (68, 546, etc.)")
		dstPort  = flag.Int("dstport", 0, "Destination port filter (67, 547, 80, 443, etc.)")
		protocol = flag.String("protocol", "", "Protocol filter (icmp, tcp, udp)")
		// API mode flag
		useAPI = flag.Bool("use-api", false, "Use HTTP API via capture server instead of vppctl commands")
	)

	// Custom usage function
	flag.Usage = func() {
		printHelp()
	}

	// Manually parse arguments to handle global flags anywhere in the command line
	var command string
	var commandArgs []string
	var remainingArgs []string

	// Separate command from flags
	args := os.Args[1:] // Skip program name
	commandFound := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Check if this is a known command
		if !commandFound && !strings.HasPrefix(arg, "-") {
			switch arg {
			case "vppctl", "log", "clear", "export", "exportnode", "gdb", "sh", "trace", "pcap", "dispatch", "capture":
				command = arg
				commandFound = true
				commandArgs = args[i+1:]
			}
		}

		if !commandFound {
			remainingArgs = append(remainingArgs, arg)
		}
	}

	// If no command found, check if we need help
	if command == "" {
		// Parse the remaining args to check for help flag
		_ = flag.CommandLine.Parse(remainingArgs)
		if *help {
			printHelp()
			return
		}
		printHelp()
		os.Exit(1)
	}

	// Now parse all arguments (including those after command) for flags
	allArgs := append(remainingArgs, commandArgs...)

	// Create a new flagset to avoid conflicts
	flagSet := flag.NewFlagSet("calicovppctl", flag.ContinueOnError)
	flagSet.Usage = func() {
		printHelp()
	}

	// Re-define flags in the new flagset
	nodeNamePtr := flagSet.String("node", "", "Node name to operate on")
	componentPtr := flagSet.String("component", "", "Component to operate on (vpp, agent, felix)")
	followPtr := flagSet.Bool("f", false, "Follow logs (for log command)")
	countPtr := flagSet.Int("count", 1000, "Packet count for trace/pcap/dispatch commands")
	timeoutPtr := flagSet.Int("timeout", 30, "Timeout in seconds for trace/pcap/dispatch commands")
	interfacePtr := flagSet.String("interface", "", "Interface: types (memif,tuntap,vcl) for trace/dispatch; interface names for pcap")
	outputPtr := flagSet.String("output", "", "Output file for pcap/dispatch commands")
	helpPtr := flagSet.Bool("help", false, "Show help message")
	// BPF filter flags
	srcIPPtr := flagSet.String("srcip", "", "Source IP address filter")
	dstIPPtr := flagSet.String("dstip", "", "Destination IP address filter")
	srcPortPtr := flagSet.Int("srcport", 0, "Source port filter")
	dstPortPtr := flagSet.Int("dstport", 0, "Destination port filter")
	protocolPtr := flagSet.String("protocol", "", "Protocol filter (tcp, udp, icmp)")
	// API mode flag
	useAPIPtr := flagSet.Bool("use-api", false, "Use HTTP API via capture server")

	// Parse all remaining arguments for flags
	var finalCommandArgs []string
	for i := 0; i < len(allArgs); i++ {
		arg := allArgs[i]
		if strings.HasPrefix(arg, "-") {
			// This is a flag, try to parse it
			switch arg {
			case "-node", "--node", "-n":
				if i+1 < len(allArgs) {
					*nodeNamePtr = allArgs[i+1]
					i++ // Skip the next argument as it's the value
				}
			case "-component", "--component", "-c":
				if i+1 < len(allArgs) {
					*componentPtr = allArgs[i+1]
					i++ // Skip the next argument as it's the value
				}
			case "-count", "--count":
				if i+1 < len(allArgs) {
					if countVal, err := strconv.Atoi(allArgs[i+1]); err == nil {
						*countPtr = countVal
					}
					i++ // Skip the next argument as it's the value
				}
			case "-timeout", "--timeout", "-t":
				if i+1 < len(allArgs) {
					if timeoutVal, err := strconv.Atoi(allArgs[i+1]); err == nil {
						*timeoutPtr = timeoutVal
					}
					i++ // Skip the next argument as it's the value
				}
			case "-interface", "--interface", "-i":
				if i+1 < len(allArgs) {
					*interfacePtr = allArgs[i+1]
					i++ // Skip the next argument as it's the value
				}
			case "-output", "--output", "-o", "-out":
				if i+1 < len(allArgs) {
					*outputPtr = allArgs[i+1]
					i++ // Skip the next argument as it's the value
				}
			case "-f":
				*followPtr = true
			case "-help", "--help", "-h":
				*helpPtr = true
			case "-srcip", "--srcip":
				if i+1 < len(allArgs) {
					*srcIPPtr = allArgs[i+1]
					i++
				}
			case "-dstip", "--dstip":
				if i+1 < len(allArgs) {
					*dstIPPtr = allArgs[i+1]
					i++
				}
			case "-srcport", "--srcport":
				if i+1 < len(allArgs) {
					if portVal, err := strconv.Atoi(allArgs[i+1]); err == nil {
						*srcPortPtr = portVal
					}
					i++
				}
			case "-dstport", "--dstport":
				if i+1 < len(allArgs) {
					if portVal, err := strconv.Atoi(allArgs[i+1]); err == nil {
						*dstPortPtr = portVal
					}
					i++
				}
			case "-protocol", "--protocol", "-proto":
				if i+1 < len(allArgs) {
					*protocolPtr = allArgs[i+1]
					i++
				}
			case "-use-api", "--use-api":
				*useAPIPtr = true
			}
		} else {
			// This is not a flag, add to final command args
			finalCommandArgs = append(finalCommandArgs, arg)
		}
	}

	// Update the original flag variables
	*nodeName = *nodeNamePtr
	*component = *componentPtr
	*follow = *followPtr
	*count = *countPtr
	*timeout = *timeoutPtr
	*interfaceType = *interfacePtr
	*output = *outputPtr
	*help = *helpPtr
	*srcIP = *srcIPPtr
	*dstIP = *dstIPPtr
	*srcPort = *srcPortPtr
	*dstPort = *dstPortPtr
	*protocol = *protocolPtr
	*useAPI = *useAPIPtr

	// Show help if requested
	if *help {
		printHelp()
		return
	}

	commandArgs = finalCommandArgs

	// Create Kubernetes client
	k, err := newKubeClient()
	if err != nil {
		handleError(err, "Failed to create Kubernetes client")
	}

	switch command {
	case "vppctl":
		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for vppctl command. Use -node flag"), "")
		}

		validatedNode, err := validateNodeName(k, *nodeName)
		if err != nil {
			handleError(err, "Node validation failed")
		}

		// If no additional arguments, start interactive mode
		if len(commandArgs) == 0 {
			podName, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
			if err != nil {
				handleError(err, "Pod not found")
			}

			// Run interactive vppctl session
			cmd := exec.Command(kubectlCmd, "exec", "-it", "-n", defaultNamespace,
				"-c", defaultContainerVpp, podName, "--",
				vppctlPath, "-s", vppSockPath)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				handleError(err, "vppctl interactive mode failed")
			}
		} else {
			// Execute single command mode
			output, err := k.vppctl(validatedNode, commandArgs...)
			if err != nil {
				handleError(err, "vppctl failed")
			}
			fmt.Println(output)
		}

	case "log":
		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for log command. Use -node flag"), "")
		}

		err := printLogs(k, *nodeName, *component, *follow)
		if err != nil {
			handleError(err, "Failed to print logs")
		}

	case "clear":
		err := clearVppStats(k)
		if err != nil {
			handleError(err, "Failed to clear stats")
		}

	case "export":
		err := exportData(k, "")
		if err != nil {
			handleError(err, "Export failed")
		}

	case "exportnode":
		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for exportnode command. Use -node flag"), "")
		}

		validatedNode, err := validateNodeName(k, *nodeName)
		if err != nil {
			handleError(err, "Node validation failed")
		}

		err = exportData(k, validatedNode)
		if err != nil {
			handleError(err, "Export failed")
		}

	case "gdb":
		// Find the VPP docker container
		printColored("grey", "This finds the VPP running in a vpp_calico-vpp docker container")
		printColored("grey", "and attaches to it. [Ctrl+C detach q ENTER] to exit")

		containerCmd := exec.Command(dockerCmd, "ps", "--filter", "name=vpp_calico-vpp", "--format", "{{.ID}}")
		containerOutput, err := containerCmd.Output()
		if err != nil || len(containerOutput) == 0 {
			handleError(fmt.Errorf("no vpp container found"), "")
		}

		containerID := strings.TrimSpace(string(containerOutput))

		// Get VPP PID
		pidCmd := exec.Command(dockerCmd, "exec", containerID, "cat", "/var/run/vpp/vpp.pid")
		pidOutput, err := pidCmd.Output()
		if err != nil {
			handleError(err, "Failed to get VPP PID")
		}

		pid := strings.TrimSpace(string(pidOutput))

		// Attach GDB
		gdbCmd := exec.Command(dockerCmd, "exec", "-it", containerID, "gdb", "-p", pid, "-ex", "continue")
		gdbCmd.Stdin = os.Stdin
		gdbCmd.Stdout = os.Stdout
		gdbCmd.Stderr = os.Stderr
		err = gdbCmd.Run()
		if err != nil {
			handleError(err, "GDB failed")
		}

	case "sh":
		if *component == "" {
			handleError(fmt.Errorf("component is required for sh command. Use -component flag with 'vpp' or 'agent'"), "")
		}

		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for sh command. Use -node flag"), "")
		}

		err := getShell(k, *component, *nodeName)
		if err != nil {
			handleError(err, "Shell failed")
		}

	case "trace":
		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for trace command. Use -node flag"), "")
		}

		if *useAPI {
			err := traceCommandAPI(k, *nodeName, *count, *timeout, *interfaceType, *srcIP, *dstIP, *protocol, *srcPort, *dstPort)
			if err != nil {
				handleError(err, "Trace (API) failed")
			}
		} else {
			err := traceCommand(k, *nodeName, *count, *timeout, *interfaceType, *srcIP, *dstIP, *protocol, *srcPort, *dstPort)
			if err != nil {
				handleError(err, "Trace failed")
			}
		}

	case "pcap":
		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for pcap command. Use -node flag"), "")
		}

		if *useAPI {
			err := pcapCommandAPI(k, *nodeName, *count, *timeout, *interfaceType, *output, *srcIP, *dstIP, *protocol, *srcPort, *dstPort)
			if err != nil {
				handleError(err, "PCAP (API) failed")
			}
		} else {
			err := pcapCommand(k, *nodeName, *count, *timeout, *interfaceType, *output, *srcIP, *dstIP, *protocol, *srcPort, *dstPort)
			if err != nil {
				handleError(err, "PCAP failed")
			}
		}

	case "dispatch":
		if *nodeName == "" {
			handleError(fmt.Errorf("node name is required for dispatch command. Use -node flag"), "")
		}

		if *useAPI {
			err := dispatchCommandAPI(k, *nodeName, *count, *timeout, *interfaceType, *output, *srcIP, *dstIP, *protocol, *srcPort, *dstPort)
			if err != nil {
				handleError(err, "Dispatch (API) failed")
			}
		} else {
			err := dispatchCommand(k, *nodeName, *count, *timeout, *interfaceType, *output, *srcIP, *dstIP, *protocol, *srcPort, *dstPort)
			if err != nil {
				handleError(err, "Dispatch failed")
			}
		}

	case "capture":
		if len(commandArgs) == 0 {
			handleError(fmt.Errorf("capture command requires a subcommand. Use 'capture clear', 'capture status', or 'capture stop'"), "")
		}

		switch commandArgs[0] {
		case "clear":
			if *nodeName == "" {
				handleError(fmt.Errorf("node name is required for capture clear command. Use -node flag"), "")
			}

			err := captureCleanupCommand(k, *nodeName)
			if err != nil {
				handleError(err, "Capture cleanup failed")
			}

		case "status":
			if *nodeName == "" {
				handleError(fmt.Errorf("node name is required for capture status command. Use -node flag"), "")
			}

			err := captureStatusCommand(k, *nodeName)
			if err != nil {
				handleError(err, "Capture status failed")
			}

		case "stop":
			if *nodeName == "" {
				handleError(fmt.Errorf("node name is required for capture stop command. Use -node flag"), "")
			}

			err := captureStopCommand(k, *nodeName, *output)
			if err != nil {
				handleError(err, "Capture stop failed")
			}

		default:
			handleError(fmt.Errorf("unknown capture subcommand: %s. Use 'capture clear', 'capture status', or 'capture stop'", commandArgs[0]), "")
		}

	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

// getPodLogsFiltered gets logs for a pod and optionally filters them
func getPodLogsFiltered(k *KubeClient, namespace, podName, containerName string, follow bool, filter func(string) bool) (string, error) {
	logs, err := k.getPodLogs(namespace, podName, containerName, follow)
	if err != nil {
		return "", err
	}

	if filter == nil {
		return logs, nil
	}

	// Apply filter
	var filteredLogs strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(logs))
	for scanner.Scan() {
		line := scanner.Text()
		if filter(line) {
			filteredLogs.WriteString(line)
			filteredLogs.WriteString("\n")
		}
	}

	return filteredLogs.String(), nil
}

// createTarGz creates a compressed tarball of the contents of sourceDir
func createTarGz(sourceDir, targetFile string) error {
	tarFile, err := os.Create(targetFile)
	if err != nil {
		return err
	}
	defer tarFile.Close()

	gzWriter := gzip.NewWriter(tarFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Get the base name of the source directory to use as the parent folder in the archive
	baseDir := filepath.Base(sourceDir)

	// Walk through the source directory
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create a tar header
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		// Set proper relative path in the archive
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// For the source directory itself, skip it
		if relPath == "." {
			return nil
		}

		// Add the base directory as parent directory in the archive
		header.Name = filepath.Join(baseDir, relPath)

		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// If this is a regular file, write its content
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(tarWriter, file)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (k *KubeClient) collectKubernetesData(exportDir, prefix string) error {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	// Get kubectl version (still using kubectl for this as it's client version)
	cmd := exec.Command(kubectlCmd, "version")
	output, _ := cmd.CombinedOutput()
	_ = writeToFile(exportDir, prefix, "kubectl-version", string(output))
	printColoredDot("grey")

	// Get all pods across all namespaces
	pods, err := k.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err == nil {
		podData := k.formatPodsWide(pods.Items)
		_ = writeToFile(exportDir, prefix, "get-pods", podData)
	}
	printColoredDot("grey")

	// Get all services across all namespaces
	services, err := k.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err == nil {
		serviceData := k.formatServicesWide(services.Items)
		_ = writeToFile(exportDir, prefix, "get-services", serviceData)
	}
	printColoredDot("grey")

	// Get all nodes
	nodes, err := k.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err == nil {
		nodeData := k.formatNodesWide(nodes.Items)
		_ = writeToFile(exportDir, prefix, "get-nodes", nodeData)
	}
	printColoredDot("grey")

	// Get installation (this might be a CRD, fallback to kubectl)
	cmd = exec.Command(kubectlCmd, "get", "installation", "-o", "yaml")
	output, _ = cmd.CombinedOutput()
	_ = writeToFile(exportDir, prefix, "installation.yaml", string(output))
	printColoredDot("grey")

	// Get cni-config configmap
	cniConfig, err := k.clientset.CoreV1().ConfigMaps("calico-system").Get(ctx, "cni-config", metav1.GetOptions{})
	if err == nil {
		cniConfigYaml, _ := yaml.Marshal(cniConfig)
		_ = writeToFile(exportDir, prefix, "cni-config.configmap.yaml", string(cniConfigYaml))
	}
	printColoredDot("grey")

	// Get calico-vpp-node daemonset
	daemonset, err := k.clientset.AppsV1().DaemonSets("calico-vpp-dataplane").Get(ctx, "calico-vpp-node", metav1.GetOptions{})
	if err == nil {
		daemonsetYaml, _ := yaml.Marshal(daemonset)
		_ = writeToFile(exportDir, prefix, "calico-vpp-node.daemonset.yaml", string(daemonsetYaml))
	}
	printColoredDot("grey")

	// Get calico-vpp-config configmap
	vppConfig, err := k.clientset.CoreV1().ConfigMaps("calico-vpp-dataplane").Get(ctx, "calico-vpp-config", metav1.GetOptions{})
	if err == nil {
		vppConfigYaml, _ := yaml.Marshal(vppConfig)
		_ = writeToFile(exportDir, prefix, "calico-vpp-config.configmap.yaml", string(vppConfigYaml))
	}
	printColoredDot("grey")

	return nil
}

func (k *KubeClient) formatPodsWide(pods []corev1.Pod) string {
	var output strings.Builder
	output.WriteString("NAMESPACE\tNAME\tREADY\tSTATUS\tRESTARTS\tAGE\tIP\tNODE\tNOMINATED NODE\tREADINESS GATES\n")

	for _, pod := range pods {
		ready := 0
		total := len(pod.Spec.Containers)
		for _, status := range pod.Status.ContainerStatuses {
			if status.Ready {
				ready++
			}
		}

		restarts := int32(0)
		for _, status := range pod.Status.ContainerStatuses {
			restarts += status.RestartCount
		}

		age := time.Since(pod.CreationTimestamp.Time).Truncate(time.Second)

		output.WriteString(fmt.Sprintf("%s\t%s\t%d/%d\t%s\t%d\t%s\t%s\t%s\t<none>\t<none>\n",
			pod.Namespace, pod.Name, ready, total, pod.Status.Phase, restarts,
			age, pod.Status.PodIP, pod.Spec.NodeName))
	}

	return output.String()
}

func (k *KubeClient) formatServicesWide(services []corev1.Service) string {
	var output strings.Builder
	output.WriteString("NAMESPACE\tNAME\tTYPE\tCLUSTER-IP\tEXTERNAL-IP\tPORT(S)\tAGE\tSELECTOR\n")

	for _, svc := range services {
		externalIP := "<none>"
		if len(svc.Status.LoadBalancer.Ingress) > 0 {
			externalIP = svc.Status.LoadBalancer.Ingress[0].IP
			if externalIP == "" {
				externalIP = svc.Status.LoadBalancer.Ingress[0].Hostname
			}
		} else if len(svc.Spec.ExternalIPs) > 0 {
			externalIP = strings.Join(svc.Spec.ExternalIPs, ",")
		}

		var ports []string
		for _, port := range svc.Spec.Ports {
			if port.NodePort != 0 {
				ports = append(ports, fmt.Sprintf("%d:%d/%s", port.Port, port.NodePort, port.Protocol))
			} else {
				ports = append(ports, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
			}
		}
		portsStr := strings.Join(ports, ",")
		if portsStr == "" {
			portsStr = "<none>"
		}

		var selector []string
		for k, v := range svc.Spec.Selector {
			selector = append(selector, fmt.Sprintf("%s=%s", k, v))
		}
		selectorStr := strings.Join(selector, ",")
		if selectorStr == "" {
			selectorStr = "<none>"
		}

		age := time.Since(svc.CreationTimestamp.Time).Truncate(time.Second)

		output.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			svc.Namespace, svc.Name, svc.Spec.Type, svc.Spec.ClusterIP,
			externalIP, portsStr, age, selectorStr))
	}

	return output.String()
}

func (k *KubeClient) formatNodesWide(nodes []corev1.Node) string {
	var output strings.Builder
	output.WriteString("NAME\tSTATUS\tROLES\tAGE\tVERSION\tINTERNAL-IP\tEXTERNAL-IP\tOS-IMAGE\tKERNEL-VERSION\tCONTAINER-RUNTIME\n")

	for _, node := range nodes {
		status := "NotReady"
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
				status = "Ready"
				break
			}
		}

		var roles []string
		for label := range node.Labels {
			if strings.HasPrefix(label, "node-role.kubernetes.io/") {
				role := strings.TrimPrefix(label, "node-role.kubernetes.io/")
				if role == "" {
					role = "master"
				}
				roles = append(roles, role)
			}
		}
		rolesStr := strings.Join(roles, ",")
		if rolesStr == "" {
			rolesStr = "<none>"
		}

		internalIP := "<none>"
		externalIP := "<none>"
		for _, addr := range node.Status.Addresses {
			switch addr.Type {
			case corev1.NodeInternalIP:
				internalIP = addr.Address
			case corev1.NodeExternalIP:
				externalIP = addr.Address
			}
		}

		age := time.Since(node.CreationTimestamp.Time).Truncate(time.Second)

		output.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			node.Name, status, rolesStr, age, node.Status.NodeInfo.KubeletVersion,
			internalIP, externalIP, node.Status.NodeInfo.OSImage,
			node.Status.NodeInfo.KernelVersion, node.Status.NodeInfo.ContainerRuntimeVersion))
	}

	return output.String()
}

func compressAndSaveRemoteFile(k *KubeClient, nodeName, remoteFile, localFile string) error {
	namespace := defaultNamespace
	container := defaultContainerVpp

	// Find the pod on the specified node
	podName, err := k.findNodePod(nodeName, defaultPod, namespace)
	if err != nil {
		return fmt.Errorf("could not find calico-vpp-node pod on node '%s': %v", nodeName, err)
	}

	// Check if remote file exists and has content; remove it if empty
	checkCmd := fmt.Sprintf(`test -s %q || { rm -f %q; exit 3; }`, remoteFile, remoteFile)
	_, err = k.execInPod(namespace, podName, container, "sh", "-c", checkCmd)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
			fmt.Println()
			printColored("red", "No packets were captured with the specified filter.")
			printColored("grey", "This could mean:")
			printColored("grey", "  - No matching traffic occurred during the capture period")
			printColored("grey", "  - The filter expression may be too restrictive")
			printColored("grey", "  - Try running without filters to verify if there is traffic")
			return nil
		}
		return fmt.Errorf("failed to check remote file: %v", err)
	}

	printColored("green", fmt.Sprintf("Compressing and downloading file from node '%s'", nodeName))
	printColored("grey", fmt.Sprintf("Pod: %s", podName))
	printColored("grey", fmt.Sprintf("Remote file: %s", remoteFile))
	printColored("grey", fmt.Sprintf("Local file: %s", localFile))
	fmt.Println()

	// Compress remote file
	printColored("blue", "Compressing remote file...")
	remoteBasename := filepath.Base(remoteFile)
	compressCmd := fmt.Sprintf("gzip -c %s > /tmp/%s.gz", remoteFile, remoteBasename)
	_, err = k.execInPod(namespace, podName, container, "sh", "-c", compressCmd)
	if err != nil {
		return fmt.Errorf("failed to compress remote file: %v", err)
	}

	// Copy compressed file
	printColored("blue", "Copying compressed file...")

	copyCmd := exec.Command(kubectlCmd, "cp",
		fmt.Sprintf("%s/%s:/tmp/%s.gz", namespace, podName, remoteBasename),
		localFile, "-c", container)
	err = copyCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	// Clean up remote files
	printColored("blue", "Cleaning up remote file...")
	cleanupCmd := fmt.Sprintf("rm -f %s /tmp/%s.gz", remoteFile, remoteBasename)
	_, err = k.execInPod(namespace, podName, container, "sh", "-c", cleanupCmd)
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to clean up remote files: %v", err))
	}

	fmt.Println()
	printColored("green", fmt.Sprintf("File successfully saved to %s", localFile))

	return nil
}

// getVppDriverFromConfigMap retrieves the vppDriver from the calico-vpp-config ConfigMap
func getVppDriverFromConfigMap(k *KubeClient) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	configMap, err := k.clientset.CoreV1().ConfigMaps("calico-vpp-dataplane").Get(ctx, "calico-vpp-config", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get calico-vpp-config ConfigMap: %v", err)
	}

	interfacesData, exists := configMap.Data["CALICOVPP_INTERFACES"]
	if !exists {
		return "", fmt.Errorf("CALICOVPP_INTERFACES not found in ConfigMap")
	}

	// Parse the JSON directly instead of using kubectl + jq
	var interfacesConfig struct {
		UplinkInterfaces []struct {
			VppDriver string `json:"vppDriver"`
		} `json:"uplinkInterfaces"`
	}

	err = json.Unmarshal([]byte(interfacesData), &interfacesConfig)
	if err != nil {
		return "", fmt.Errorf("failed to parse CALICOVPP_INTERFACES JSON: %v", err)
	}

	if len(interfacesConfig.UplinkInterfaces) == 0 {
		return "", fmt.Errorf("no uplink interfaces found in configuration")
	}

	driver := strings.TrimSpace(interfacesConfig.UplinkInterfaces[0].VppDriver)
	if driver == "" {
		return "", fmt.Errorf("vppDriver not found or is empty")
	}

	return driver, nil
}

// mapInterfaceTypeToVppInputNode maps interface types to VPP graph input nodes
func mapInterfaceTypeToVppInputNode(k *KubeClient, interfaceType string) (string, string, error) {
	switch interfaceType {
	case "phy":
		// Get the actual VPP driver from the ConfigMap
		actualDriver, err := getVppDriverFromConfigMap(k)
		if err != nil {
			return "", "", fmt.Errorf("failed to get VPP driver from ConfigMap: %v", err)
		}
		// Recursively call with the actual driver
		return mapInterfaceTypeToVppInputNode(k, actualDriver)
	case "af_xdp":
		return "af-xdp-input", "af_xdp", nil
	case "af_packet":
		return "af-packet-input", "af_packet", nil
	case "avf":
		return "avf-input", "avf", nil
	case "vmxnet3":
		return "vmxnet3-input", "vmxnet3", nil
	case "virtio", "tuntap":
		return "virtio-input", "virtio", nil
	case "rdma":
		return "rdma-input", "rdma", nil
	case "dpdk":
		return "dpdk-input", "dpdk", nil
	case "memif":
		return "memif-input", "memif", nil
	case "vcl":
		return "session-queue", "vcl", nil
	case "":
		return "virtio-input", "virtio", nil // default to tuntap (virtio)
	default:
		errorMsg := fmt.Sprintf("Invalid interface type: %s\n\nSupported interface types:\n", interfaceType)
		errorMsg += "  phy       : use the physical interface driver configured in calico-vpp-config\n"
		errorMsg += "  af_xdp    : use an AF_XDP socket to drive the interface\n"
		errorMsg += "  af_packet : use an AF_PACKET socket to drive the interface\n"
		errorMsg += "  avf       : use the VPP native driver for Intel 700-Series and 800-Series interfaces\n"
		errorMsg += "  vmxnet3   : use the VPP native driver for VMware virtual interfaces\n"
		errorMsg += "  virtio    : use the VPP native driver for Virtio virtual interfaces\n"
		errorMsg += "  tuntap    : alias for virtio (default)\n"
		errorMsg += "  rdma      : use the VPP native driver for Mellanox CX-4 and CX-5 interfaces\n"
		errorMsg += "  dpdk      : use the DPDK interface drivers with VPP\n"
		errorMsg += "  memif     : use shared memory interfaces (memif)\n"
		errorMsg += "  vcl       : capture packets at the session layer\n"
		errorMsg += "\nDefault: virtio (if no interface type is specified)"
		return "", "", fmt.Errorf("%s", errorMsg)
	}
}

// The following functions are used with the --use-api flag when calicovppctl uses the HTTP capture server (binary API)

// callCaptureAPI calls the capture server API via kubectl exec curl
func (k *KubeClient) callCaptureAPI(nodeName, endpoint string, queryParams map[string]string) (string, error) {
	// Find the agent pod on the specified node
	podName, err := k.findNodePod(nodeName, defaultPod, defaultNamespace)
	if err != nil {
		return "", fmt.Errorf("could not find calico-vpp-node pod on node '%s': %v", nodeName, err)
	}

	// Build URL with query parameters
	url := fmt.Sprintf("http://localhost:%d/api/%s", captureServerPort, endpoint)
	if len(queryParams) > 0 {
		var params []string
		for key, value := range queryParams {
			if value != "" {
				params = append(params, fmt.Sprintf("%s=%s", key, value))
			}
		}
		if len(params) > 0 {
			url += "?" + strings.Join(params, "&")
		}
	}

	// Execute curl via kubectl exec in the agent container
	curlCmd := fmt.Sprintf("curl -s '%s'", url)
	output, err := k.execInPod(defaultNamespace, podName, defaultContainerAgt, "sh", "-c", curlCmd)
	if err != nil {
		return "", fmt.Errorf("failed to call capture API: %v", err)
	}

	return output, nil
}

// getCaptureStatus gets the current status from the capture server
func (k *KubeClient) getCaptureStatus(nodeName string) (*StatusResponse, error) {
	output, err := k.callCaptureAPI(nodeName, "status", nil)
	if err != nil {
		return nil, err
	}

	var status StatusResponse
	err = json.Unmarshal([]byte(output), &status)
	if err != nil {
		return nil, fmt.Errorf("failed to parse status response: %v", err)
	}

	return &status, nil
}

// startCaptureAPI starts a capture via the capture server API
func (k *KubeClient) startCaptureAPI(nodeName, captureType string, count, timeout int, interfaceType, srcIP, dstIP, protocol string, srcPort, dstPort int) (*CaptureResponse, error) {
	params := map[string]string{
		"count":   fmt.Sprintf("%d", count),
		"timeout": fmt.Sprintf("%d", timeout),
	}

	if interfaceType != "" {
		params["interfaceType"] = interfaceType
	}
	if srcIP != "" {
		params["srcIP"] = srcIP
	}
	if dstIP != "" {
		params["dstIP"] = dstIP
	}
	if protocol != "" {
		params["protocol"] = protocol
	}
	if srcPort > 0 {
		params["srcPort"] = fmt.Sprintf("%d", srcPort)
	}
	if dstPort > 0 {
		params["dstPort"] = fmt.Sprintf("%d", dstPort)
	}

	output, err := k.callCaptureAPI(nodeName, captureType, params)
	if err != nil {
		return nil, err
	}

	var response CaptureResponse
	err = json.Unmarshal([]byte(output), &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse capture response: %v", err)
	}

	return &response, nil
}

// stopCaptureAPI stops the current capture via the capture server API
func (k *KubeClient) stopCaptureAPI(nodeName string) (*CaptureResponse, error) {
	output, err := k.callCaptureAPI(nodeName, "stop", nil)
	if err != nil {
		return nil, err
	}

	var response CaptureResponse
	err = json.Unmarshal([]byte(output), &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stop response: %v", err)
	}

	return &response, nil
}

func printBpfFilterParams(srcIP, dstIP, protocol string, srcPort, dstPort int) {
	printColored("grey", "BPF Filter parameters:")
	if srcIP != "" {
		printColored("grey", fmt.Sprintf("  Source IP: %s", srcIP))
	}
	if dstIP != "" {
		printColored("grey", fmt.Sprintf("  Destination IP: %s", dstIP))
	}
	if protocol != "" {
		printColored("grey", fmt.Sprintf("  Protocol: %s", protocol))
	}
	if srcPort > 0 {
		printColored("grey", fmt.Sprintf("  Source Port: %d", srcPort))
	}
	if dstPort > 0 {
		printColored("grey", fmt.Sprintf("  Destination Port: %d", dstPort))
	}
	fmt.Println()
}

// traceCommandAPI runs trace using the capture server API
func traceCommandAPI(k *KubeClient, nodeName string, count int, timeout int, interfaceType, srcIP, dstIP, protocol string, srcPort, dstPort int) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	printColored("green", fmt.Sprintf("Starting packet trace via API on node '%s'", validatedNode))
	printColored("grey", fmt.Sprintf("Packet count: %d", count))
	printColored("grey", fmt.Sprintf("Timeout: %d seconds", timeout))
	if interfaceType != "" {
		printColored("grey", fmt.Sprintf("Interface type: %s", interfaceType))
	}
	if srcIP != "" || dstIP != "" || protocol != "" || srcPort > 0 || dstPort > 0 {
		printBpfFilterParams(srcIP, dstIP, protocol, srcPort, dstPort)
	}

	// Start capture via API
	response, err := k.startCaptureAPI(validatedNode, "trace", count, timeout, interfaceType, srcIP, dstIP, protocol, srcPort, dstPort)
	if err != nil {
		return fmt.Errorf("failed to start trace: %v", err)
	}

	if !response.Success {
		return fmt.Errorf("trace failed: %s (error: %s)", response.Message, response.Error)
	}

	printColored("green", response.Message)
	fmt.Println()
	printColored("blue", fmt.Sprintf("Capture will auto-stop after %d seconds or when %d packets are captured", timeout, count))
	printColored("grey", "Use 'calicovppctl capture status -node <node>' to check capture progress")
	printColored("grey", "Use 'calicovppctl capture stop -node <node>' to stop and download the capture file")

	return nil
}

// pcapCommandAPI runs pcap using the capture server API
func pcapCommandAPI(k *KubeClient, nodeName string, count int, timeout int, interfaceType, outputFile, srcIP, dstIP, protocol string, srcPort, dstPort int) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	printColored("green", fmt.Sprintf("Starting PCAP capture via API on node '%s'", validatedNode))
	printColored("grey", fmt.Sprintf("Packet count: %d", count))
	printColored("grey", fmt.Sprintf("Timeout: %d seconds", timeout))
	if interfaceType != "" {
		printColored("grey", fmt.Sprintf("Interface: %s", interfaceType))
	}
	if srcIP != "" || dstIP != "" || protocol != "" || srcPort > 0 || dstPort > 0 {
		printBpfFilterParams(srcIP, dstIP, protocol, srcPort, dstPort)
	}

	// Start capture via API
	response, err := k.startCaptureAPI(validatedNode, "pcap", count, timeout, interfaceType, srcIP, dstIP, protocol, srcPort, dstPort)
	if err != nil {
		return fmt.Errorf("failed to start pcap: %v", err)
	}

	if !response.Success {
		return fmt.Errorf("pcap failed: %s (error: %s)", response.Message, response.Error)
	}

	printColored("green", response.Message)
	fmt.Println()
	printColored("blue", fmt.Sprintf("Capture will auto-stop after %d seconds or when %d packets are captured", timeout, count))
	printColored("grey", "Use 'calicovppctl capture status -node <node>' to check capture progress")
	printColored("grey", "Use 'calicovppctl capture stop -node <node>' to stop and download the capture file")

	return nil
}

// dispatchCommandAPI runs dispatch using the capture server API
func dispatchCommandAPI(k *KubeClient, nodeName string, count int, timeout int, interfaceType, outputFile, srcIP, dstIP, protocol string, srcPort, dstPort int) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	printColored("green", fmt.Sprintf("Starting dispatch trace via API on node '%s'", validatedNode))
	printColored("grey", fmt.Sprintf("Packet count: %d", count))
	printColored("grey", fmt.Sprintf("Timeout: %d seconds", timeout))
	if interfaceType != "" {
		printColored("grey", fmt.Sprintf("Interface type: %s", interfaceType))
	}
	if srcIP != "" || dstIP != "" || protocol != "" || srcPort > 0 || dstPort > 0 {
		printBpfFilterParams(srcIP, dstIP, protocol, srcPort, dstPort)
	}

	// Start capture via API
	response, err := k.startCaptureAPI(validatedNode, "dispatch", count, timeout, interfaceType, srcIP, dstIP, protocol, srcPort, dstPort)
	if err != nil {
		return fmt.Errorf("failed to start dispatch: %v", err)
	}

	if !response.Success {
		return fmt.Errorf("dispatch failed: %s (error: %s)", response.Message, response.Error)
	}

	printColored("green", response.Message)
	fmt.Println()
	printColored("blue", fmt.Sprintf("Capture will auto-stop after %d seconds or when %d packets are captured", timeout, count))
	printColored("grey", "Use 'calicovppctl capture status -node <node>' to check capture progress")
	printColored("grey", "Use 'calicovppctl capture stop -node <node>' to stop and download the capture file")

	return nil
}

// captureStatusCommand shows the current capture status via API
func captureStatusCommand(k *KubeClient, nodeName string) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	status, err := k.getCaptureStatus(validatedNode)
	if err != nil {
		return fmt.Errorf("failed to get status: %v", err)
	}

	printColored("green", fmt.Sprintf("Capture status on node '%s':", validatedNode))
	printColored("grey", fmt.Sprintf("  Status: %s", status.Status))
	if status.CaptureType != "" {
		printColored("grey", fmt.Sprintf("  Capture Type: %s", status.CaptureType))
	}
	if status.FilePath != "" {
		printColored("grey", fmt.Sprintf("  File Path: %s", status.FilePath))
	}
	if status.RemainingMs > 0 {
		printColored("grey", fmt.Sprintf("  Time Remaining: %.1f seconds", float64(status.RemainingMs)/1000))
	}

	return nil
}

// captureStopCommand stops the current capture (if running) and downloads the capture file
// Handles multiple scenarios:
// 1) Capture is still running -> stop it, then download file
// 2) Capture already stopped (timeout/packet count reached) -> just download file
// 3) No capture was started or file already downloaded -> error message
func captureStopCommand(k *KubeClient, nodeName string, outputFile string) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	// First, get current status to understand the state
	status, err := k.getCaptureStatus(validatedNode)
	if err != nil {
		return fmt.Errorf("failed to get capture status: %v", err)
	}

	captureType := status.CaptureType
	filePath := status.FilePath

	// If capture is running, stop it first
	switch status.Status {
	case "running":
		printColored("blue", fmt.Sprintf("Stopping active %s capture on node '%s'...", captureType, validatedNode))
		response, err := k.stopCaptureAPI(validatedNode)
		if err != nil {
			return fmt.Errorf("failed to stop capture: %v", err)
		}
		if !response.Success {
			printColored("red", fmt.Sprintf("Warning: Stop returned: %s", response.Message))
		} else {
			printColored("green", "Capture stopped successfully")
		}
		// Use file path from stop response if available
		if response.FilePath != "" {
			filePath = response.FilePath
		}
	case "idle":
		// Capture is not running - check if there's a file path from previous capture
		if filePath == "" && captureType == "" {
			return fmt.Errorf("no capture is running and no previous capture file found on node '%s'.\n"+
				"Either no capture was started, or the file was already downloaded and cleaned up.\n"+
				"Start a new capture with 'calicovppctl trace/pcap/dispatch -node %s --use-api'", validatedNode, validatedNode)
		}
		printColored("blue", fmt.Sprintf("Capture already stopped on node '%s', downloading file...", validatedNode))
	}

	// Determine remote and local file paths based on capture type
	var remoteFile, localFile string
	switch captureType {
	case "trace":
		remoteFile = "/var/run/vpp/trace.txt"
		localFile = "./trace.txt.gz"
	case "pcap":
		remoteFile = "/tmp/trace.pcap"
		localFile = "./trace.pcap.gz"
	case "dispatch":
		remoteFile = "/tmp/dispatch.pcap"
		localFile = "./dispatch.pcap.gz"
	default:
		// Try to infer from filePath if captureType is empty
		if filePath != "" {
			remoteFile = filePath
			localFile = "./" + filepath.Base(filePath) + ".gz"
		} else {
			return fmt.Errorf("unknown capture type and no file path available")
		}
	}

	// Override local file if user specified output
	if outputFile != "" {
		localFile = outputFile
		if !strings.HasSuffix(localFile, ".gz") {
			localFile = localFile + ".gz"
		}
	}

	// Download the file
	err = compressAndSaveRemoteFile(k, validatedNode, remoteFile, localFile)
	// Check if file doesn't exist (already downloaded or never created)
	if err != nil {
		return fmt.Errorf("failed to download capture file: %v\n"+
			"The file may have already been downloaded and cleaned up, or the capture produced no output", err)
	}

	return nil
}

// The following functions are used when calicovppctl runs in the legacy mode with vppctl commands via "kubectl exec"

func traceCommand(k *KubeClient, nodeName string, count int, timeout int, interfaceType, srcIP, dstIP, protocol string, srcPort, dstPort int) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	// Check for existing capture locks
	lockInfo, err := checkCaptureLock(k, validatedNode)
	if err != nil {
		return fmt.Errorf("failed to check capture lock: %v", err)
	}
	if lockInfo != nil {
		return fmt.Errorf("capture operation already running on node '%s'\n"+
			"  Operation: %s\n"+
			"  Started by: %s\n"+
			"  Started at: %s\n"+
			"  BPF filters active: %t\n\n"+
			"Use 'calicovppctl capture clear -node %s' to force cleanup if the previous operation failed",
			validatedNode, lockInfo.Operation, lockInfo.Hostname,
			lockInfo.StartedAt.Format("2006-01-02 15:04:05"), lockInfo.BPFActive, validatedNode)
	}

	// Check if BPF filters will be used
	bpfFilter := buildBPFFilter(srcIP, dstIP, protocol, srcPort, dstPort)
	useBPF := bpfFilter != ""

	// Create capture lock
	err = createCaptureLock(k, validatedNode, "trace", useBPF)
	if err != nil {
		return fmt.Errorf("failed to create capture lock: %v", err)
	}

	// Ensure cleanup on exit
	defer func() {
		err := removeCaptureLock(k, validatedNode)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Failed to remove capture lock: %v", err))
		}
	}()

	vppInputNode, _, err := mapInterfaceTypeToVppInputNode(k, interfaceType)
	if err != nil {
		return err
	}

	printColored("green", fmt.Sprintf("Starting packet trace on node '%s'", validatedNode))
	printColored("grey", fmt.Sprintf("Packet count: %d", count))
	printColored("grey", fmt.Sprintf("Timeout: %d seconds", timeout))
	printColored("grey", fmt.Sprintf("VPP Input Node: %s", vppInputNode))
	printColored("grey", "Output file: ./trace.txt.gz")

	// Apply BPF filter if specified
	if bpfFilter != "" {
		printColored("grey", fmt.Sprintf("BPF Filter: %s", bpfFilter))
		err := applyBPFFilter(k, validatedNode, bpfFilter, false)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Failed to apply BPF filter: %v", err))
			printColored("grey", "Continuing without filter...")
		} else {
			useBPF = true
			defer func() {
				printColored("blue", "Clearing BPF filter...")
				err := clearBPFFilter(k, validatedNode, false)
				if err != nil {
					printColored("red", fmt.Sprintf("Warning: Failed to clear BPF filter: %v", err))
				}
			}()
		}
	}
	fmt.Println()

	// Clear any existing traces first
	_, err = k.vppctl(validatedNode, "clear", "trace")
	if err != nil {
		return fmt.Errorf("failed to clear existing traces: %v", err)
	}

	// Add trace for specified interface type
	printColored("blue", "Starting packet trace...")
	traceCmd := []string{"trace", "add", vppInputNode, fmt.Sprintf("%d", count)}
	if useBPF {
		traceCmd = append(traceCmd, "filter")
	}
	printColored("grey", fmt.Sprintf("Command: %s", strings.Join(traceCmd, " ")))
	_, err = k.vppctl(validatedNode, traceCmd...)
	if err != nil {
		return fmt.Errorf("failed to add trace: %v", err)
	}

	fmt.Println()
	printColored("green", fmt.Sprintf("Packet trace configured. Will auto-stop after %d seconds or press Ctrl+C to stop early...", timeout))
	fmt.Println()

	// Channel to signal the monitoring goroutine to stop
	stopChan := make(chan struct{})

	// Set up signal handling for Ctrl+C and timeout
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	timeoutChan := time.After(time.Duration(timeout) * time.Second)
	startTime := time.Now()

	// Start monitoring goroutine
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				remaining := max(0, timeout-int(time.Since(startTime).Seconds()))
				printColored("blue", fmt.Sprintf("=== Packet trace active on node '%s' (%ds remaining, Press Ctrl+C to stop) ===", validatedNode, remaining))
				fmt.Println()
				time.Sleep(5 * time.Second)
			}
		}
	}()

	// Wait for signal or timeout
	timeoutExpired := false
	select {
	case <-sigChan:
		// User pressed Ctrl+C
	case <-timeoutChan:
		timeoutExpired = true
	}

	// Stop monitoring
	close(stopChan)
	signal.Stop(sigChan)

	fmt.Println()
	if timeoutExpired {
		printColored("blue", fmt.Sprintf("Timeout reached (%d seconds). Stopping packet trace...", timeout))
	} else {
		printColored("blue", "Stopping packet trace...")
	}

	// Save trace output to file inside the container
	namespace := defaultNamespace
	container := defaultContainerVpp

	// Find the pod on the specified node
	podName, err := k.findNodePod(validatedNode, defaultPod, namespace)
	if err != nil {
		return fmt.Errorf("could not find calico-vpp-node pod on node '%s': %v", validatedNode, err)
	}

	// Save trace output to file inside the container using vppctl redirection
	printColored("blue", "Saving trace output to /tmp/trace.txt in vpp container...")
	fmt.Println()

	saveCmd := fmt.Sprintf("vppctl -s %s show trace max %d > /tmp/trace.txt", vppSockPath, count)
	_, err = k.execInPod(namespace, podName, container, "sh", "-c", saveCmd)
	if err != nil {
		return fmt.Errorf("failed to save trace output to file: %v", err)
	}

	// Clear trace
	_, err = k.vppctl(validatedNode, "clear", "trace")
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to clear trace: %v", err))
	}

	// Compress and save remote file
	err = compressAndSaveRemoteFile(k, validatedNode, "/tmp/trace.txt", "./trace.txt.gz")
	if err != nil {
		return fmt.Errorf("failed to save trace file: %v", err)
	}

	return nil
}

func pcapCommand(k *KubeClient, nodeName string, count int, timeout int, interfaceType, outputFile, srcIP, dstIP, protocol string, srcPort, dstPort int) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	// Check for existing capture locks
	lockInfo, err := checkCaptureLock(k, validatedNode)
	if err != nil {
		return fmt.Errorf("failed to check capture lock: %v", err)
	}
	if lockInfo != nil {
		return fmt.Errorf("capture operation already running on node '%s'\n"+
			"  Operation: %s\n"+
			"  Started by: %s\n"+
			"  Started at: %s\n"+
			"  BPF filters active: %t\n\n"+
			"Use 'calicovppctl capture clear -node %s' to force cleanup if the previous operation failed",
			validatedNode, lockInfo.Operation, lockInfo.Hostname,
			lockInfo.StartedAt.Format("2006-01-02 15:04:05"), lockInfo.BPFActive, validatedNode)
	}

	// Check if BPF filters will be used
	bpfFilter := buildBPFFilter(srcIP, dstIP, protocol, srcPort, dstPort)
	useBPF := bpfFilter != ""

	// Create capture lock
	err = createCaptureLock(k, validatedNode, "pcap", useBPF)
	if err != nil {
		return fmt.Errorf("failed to create capture lock: %v", err)
	}

	// Ensure cleanup on exit
	defer func() {
		err := removeCaptureLock(k, validatedNode)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Failed to remove capture lock: %v", err))
		}
	}()

	// First, let's validate that we can access the VPP interfaces
	interfacesOutput, err := k.vppctl(validatedNode, "show", "interface")
	if err != nil {
		return fmt.Errorf("failed to get interface list from VPP: %v", err)
	}

	upInterfaces := parseVppInterfaces(interfacesOutput)
	if len(upInterfaces) == 0 {
		return fmt.Errorf("no interfaces found or all interfaces are down on node '%s'", validatedNode)
	}

	var interfaceFilter string
	if interfaceType != "" {
		// Validate that the provided interface name exists in the UP interfaces list
		isValidInterface := false
		for _, iface := range upInterfaces {
			if iface == interfaceType {
				isValidInterface = true
				break
			}
		}

		if isValidInterface {
			// User provided a valid interface name
			interfaceFilter = interfaceType
		} else {
			// Interface not found, show available UP interfaces
			var interfaceList strings.Builder
			interfaceList.WriteString(fmt.Sprintf("Interface '%s' not found or is down.", interfaceType))
			interfaceList.WriteString("\nAvailable UP interfaces:")
			for i, iface := range upInterfaces {
				interfaceList.WriteString(fmt.Sprintf("\n%d. %s", i+1, iface))
			}
			return fmt.Errorf("%s", interfaceList.String())
		}
	} else {
		// No interface specified, use "any" to capture on all interfaces
		interfaceFilter = "any"
		printColored("grey", "No interface specified, using 'any' to capture on all interfaces")
	}

	pcapCommand := []string{
		"pcap", "trace", "tx", "rx",
		"max", fmt.Sprintf("%d", count),
		"intfc", interfaceFilter,
		"file", "trace.pcap",
	}

	printColored("green", fmt.Sprintf("Starting PCAP trace on node '%s'", validatedNode))
	printColored("grey", fmt.Sprintf("Packet count: %d", count))
	printColored("grey", fmt.Sprintf("Timeout: %d seconds", timeout))
	printColored("grey", fmt.Sprintf("Interface filter: %s", interfaceFilter))
	if outputFile != "" {
		printColored("grey", fmt.Sprintf("Output file: ./%s.gz", outputFile))
	}

	// Apply BPF filter if specified
	if bpfFilter != "" {
		printColored("grey", fmt.Sprintf("BPF Filter: %s", bpfFilter))
		err := applyBPFFilter(k, validatedNode, bpfFilter, true)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Failed to apply BPF filter: %v", err))
			printColored("grey", "Continuing without filter...")
		} else {
			useBPF = true
			defer func() {
				printColored("blue", "Clearing BPF filter...")
				err := clearBPFFilter(k, validatedNode, true)
				if err != nil {
					printColored("red", fmt.Sprintf("Warning: Failed to clear BPF filter: %v", err))
				}
			}()
		}
	}
	fmt.Println()

	printColored("blue", "Starting PCAP trace...")
	if useBPF {
		pcapCommand = append(pcapCommand, "filter")
	}
	printColored("grey", fmt.Sprintf("Command: %s", strings.Join(pcapCommand, " ")))
	_, err = k.vppctl(validatedNode, pcapCommand...)
	if err != nil {
		return fmt.Errorf("failed to start PCAP trace: %v", err)
	}

	fmt.Println()
	printColored("green", fmt.Sprintf("PCAP trace configured. Will auto-stop after %d seconds or press Ctrl+C to stop early...", timeout))
	fmt.Println()

	// Determine output filename
	var localOutputFile string
	if outputFile != "" {
		localOutputFile = fmt.Sprintf("./%s.gz", outputFile)
	} else {
		localOutputFile = fmt.Sprintf("./pcap_%s.pcap.gz", validatedNode)
	}

	// Channel to signal the monitoring goroutine to stop
	stopChan := make(chan struct{})

	// Set up signal handling for Ctrl+C and timeout
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	timeoutChan := time.After(time.Duration(timeout) * time.Second)
	startTime := time.Now()

	// Start monitoring goroutine
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				remaining := max(0, timeout-int(time.Since(startTime).Seconds()))
				printColored("blue", fmt.Sprintf("=== PCAP trace active on node '%s' (%ds remaining, Press Ctrl+C to stop) ===", validatedNode, remaining))
				fmt.Println()
				time.Sleep(5 * time.Second)
			}
		}
	}()

	// Wait for signal or timeout
	timeoutExpired := false
	select {
	case <-sigChan:
		// User pressed Ctrl+C
	case <-timeoutChan:
		timeoutExpired = true
	}

	// Stop monitoring
	close(stopChan)
	signal.Stop(sigChan)

	fmt.Println()
	if timeoutExpired {
		printColored("blue", fmt.Sprintf("Timeout reached (%d seconds). Stopping PCAP trace...", timeout))
	} else {
		printColored("blue", "Stopping PCAP trace...")
	}
	_, err = k.vppctl(validatedNode, "pcap", "trace", "off")
	if err != nil {
		return fmt.Errorf("failed to stop PCAP trace: %v", err)
	}

	printColored("green", "PCAP trace stopped")
	fmt.Println()

	// Compress and save remote file
	err = compressAndSaveRemoteFile(k, validatedNode, "/tmp/trace.pcap", localOutputFile)
	if err != nil {
		return fmt.Errorf("failed to save PCAP file: %v", err)
	}

	return nil
}

func dispatchCommand(k *KubeClient, nodeName string, count int, timeout int, interfaceType, outputFile, srcIP, dstIP, protocol string, srcPort, dstPort int) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	// Check for existing capture locks
	lockInfo, err := checkCaptureLock(k, validatedNode)
	if err != nil {
		return fmt.Errorf("failed to check capture lock: %v", err)
	}
	if lockInfo != nil {
		return fmt.Errorf("capture operation already running on node '%s'\n"+
			"  Operation: %s\n"+
			"  Started by: %s\n"+
			"  Started at: %s\n"+
			"  BPF filters active: %t\n\n"+
			"Use 'calicovppctl capture clear -node %s' to force cleanup if the previous operation failed",
			validatedNode, lockInfo.Operation, lockInfo.Hostname,
			lockInfo.StartedAt.Format("2006-01-02 15:04:05"), lockInfo.BPFActive, validatedNode)
	}

	// Check if BPF filters will be used
	bpfFilter := buildBPFFilter(srcIP, dstIP, protocol, srcPort, dstPort)
	useBPF := bpfFilter != ""

	// Create capture lock
	err = createCaptureLock(k, validatedNode, "dispatch", useBPF)
	if err != nil {
		return fmt.Errorf("failed to create capture lock: %v", err)
	}

	// Ensure cleanup on exit
	defer func() {
		err := removeCaptureLock(k, validatedNode)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Failed to remove capture lock: %v", err))
		}
	}()

	vppInputNode, _, err := mapInterfaceTypeToVppInputNode(k, interfaceType)
	if err != nil {
		return err
	}

	dispatchCmd := []string{
		"pcap", "dispatch", "trace", "on",
		"max", fmt.Sprintf("%d", count),
		"buffer-trace", vppInputNode, fmt.Sprintf("%d", count),
		"file", "dispatch.pcap",
	}

	printColored("green", fmt.Sprintf("Starting dispatch trace on node '%s'", validatedNode))
	printColored("grey", fmt.Sprintf("Packet count: %d", count))
	printColored("grey", fmt.Sprintf("Timeout: %d seconds", timeout))
	printColored("grey", fmt.Sprintf("VPP Input Node: %s", vppInputNode))
	if outputFile != "" {
		printColored("grey", fmt.Sprintf("Output file: ./%s.gz", outputFile))
	}

	// Apply BPF filter if specified
	if bpfFilter != "" {
		printColored("grey", fmt.Sprintf("BPF Filter: %s", bpfFilter))
		err := applyBPFFilter(k, validatedNode, bpfFilter, true)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Failed to apply BPF filter: %v", err))
			printColored("grey", "Continuing without filter...")
		} else {
			useBPF = true
			defer func() {
				printColored("blue", "Clearing BPF filter...")
				err := clearBPFFilter(k, validatedNode, true)
				if err != nil {
					printColored("red", fmt.Sprintf("Warning: Failed to clear BPF filter: %v", err))
				}
			}()
		}
	}
	fmt.Println()

	printColored("blue", "Starting dispatch trace...")
	if useBPF {
		dispatchCmd = append(dispatchCmd, "filter")
	}
	printColored("grey", fmt.Sprintf("Command: %s", strings.Join(dispatchCmd, " ")))
	_, err = k.vppctl(validatedNode, dispatchCmd...)
	if err != nil {
		return fmt.Errorf("failed to start dispatch trace: %v", err)
	}

	fmt.Println()
	printColored("green", fmt.Sprintf("Dispatch trace configured. Will auto-stop after %d seconds or press Ctrl+C to stop early...", timeout))
	fmt.Println()

	// Determine output filename
	var localOutputFile string
	if outputFile != "" {
		localOutputFile = fmt.Sprintf("./%s.gz", outputFile)
	} else {
		localOutputFile = fmt.Sprintf("./dispatch_%s.pcap.gz", validatedNode)
	}

	// Channel to signal the monitoring goroutine to stop
	stopChan := make(chan struct{})

	// Set up signal handling for Ctrl+C and timeout
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	timeoutChan := time.After(time.Duration(timeout) * time.Second)
	startTime := time.Now()

	// Start monitoring goroutine
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				remaining := max(0, timeout-int(time.Since(startTime).Seconds()))
				printColored("blue", fmt.Sprintf("=== Dispatch trace active on node '%s' (%ds remaining, Press Ctrl+C to stop) ===", validatedNode, remaining))
				fmt.Println()
				time.Sleep(5 * time.Second)
			}
		}
	}()

	// Wait for signal or timeout
	timeoutExpired := false
	select {
	case <-sigChan:
		// User pressed Ctrl+C
	case <-timeoutChan:
		timeoutExpired = true
	}

	// Stop monitoring
	close(stopChan)
	signal.Stop(sigChan)

	fmt.Println()
	if timeoutExpired {
		printColored("blue", fmt.Sprintf("Timeout reached (%d seconds). Stopping dispatch trace...", timeout))
	} else {
		printColored("blue", "Stopping dispatch trace...")
	}
	_, err = k.vppctl(validatedNode, "pcap", "dispatch", "trace", "off")
	if err != nil {
		return fmt.Errorf("failed to stop dispatch trace: %v", err)
	}

	printColored("green", "Dispatch trace stopped")
	fmt.Println()

	// Compress and save remote file
	err = compressAndSaveRemoteFile(k, validatedNode, "/tmp/dispatch.pcap", localOutputFile)
	if err != nil {
		return fmt.Errorf("failed to save dispatch file: %v", err)
	}

	return nil
}

// parseVppInterfaces parses the output of "show interface" and returns a list of up interfaces
func parseVppInterfaces(output string) []string {
	var upInterfaces []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// Skip empty lines and header lines
		if strings.TrimSpace(line) == "" || strings.Contains(line, "Name") || strings.Contains(line, "Counter") || strings.Contains(line, "Count") {
			continue
		}

		// Skip lines that don't start with an interface name (statistics lines, etc.)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "rx ") || strings.HasPrefix(trimmed, "tx ") ||
			strings.HasPrefix(trimmed, "drops") || strings.HasPrefix(trimmed, "punt") ||
			strings.HasPrefix(trimmed, "ip4") || strings.HasPrefix(trimmed, "ip6") {
			continue
		}

		// Look for interface lines (they start with interface name)
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Check if the line contains interface information
			// Format: "interface_name    idx    state    mtu"
			interfaceName := fields[0]
			state := fields[2]

			// Only add interfaces that are "up"
			if state == "up" && interfaceName != "" {
				upInterfaces = append(upInterfaces, interfaceName)
			}
		}
	}

	return upInterfaces
}

func validateIP(ip string) error {
	if ip == "" {
		return nil
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// buildBPFFilter constructs a BPF filter expression from the provided parameters
func buildBPFFilter(srcIP, dstIP, protocol string, srcPort, dstPort int) string {
	var filters []string

	// Add protocol filter
	if protocol != "" {
		switch strings.ToLower(protocol) {
		case "tcp":
			filters = append(filters, "tcp")
		case "udp":
			filters = append(filters, "udp")
		case "icmp":
			filters = append(filters, "icmp")
		default:
			printColored("red", fmt.Sprintf("Warning: Unknown protocol '%s', ignoring", protocol))
		}
	}

	// Add IP filters
	if srcIP != "" {
		err := validateIP(srcIP)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Invalid source IP '%s', ignoring", srcIP))
		} else {
			filters = append(filters, fmt.Sprintf("src host %s", srcIP))
		}
	}
	if dstIP != "" {
		err := validateIP(dstIP)
		if err != nil {
			printColored("red", fmt.Sprintf("Warning: Invalid destination IP '%s', ignoring", dstIP))
		} else {
			filters = append(filters, fmt.Sprintf("dst host %s", dstIP))
		}
	}

	// Add port filters
	if srcPort != 0 {
		if srcPort > 0 && srcPort < 65536 {
			filters = append(filters, fmt.Sprintf("src port %d", srcPort))
		} else {
			printColored("red", fmt.Sprintf("Warning: Invalid source port '%d', ignoring", srcPort))
		}
	}
	if dstPort != 0 {
		if dstPort > 0 && dstPort < 65536 {
			filters = append(filters, fmt.Sprintf("dst port %d", dstPort))
		} else {
			printColored("red", fmt.Sprintf("Warning: Invalid destination port '%d', ignoring", dstPort))
		}
	}

	if len(filters) == 0 {
		return ""
	}

	return strings.Join(filters, " and ")
}

func applyBPFFilter(k *KubeClient, nodeName, bpfFilter string, isPcap bool) error {
	printColored("blue", fmt.Sprintf("Applying BPF filter: %s", bpfFilter))

	// Set the BPF filter expression ()set bpf trace filter {{<expression>}})
	filterArg := fmt.Sprintf("{{%s}}", bpfFilter)
	out, err := k.vppctl(nodeName, "set", "bpf", "trace", "filter", filterArg)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}
	// Check if pcap_compile failed (VPP returns this in stdout, not as error)
	if strings.Contains(out, "Failed pcap_compile") {
		return fmt.Errorf("BPF filter compilation failed: %s", out)
	}

	// Enable BPF filtering function (set trace/pcap filter function bpf_trace_filter)
	if isPcap {
		_, err = k.vppctl(nodeName, "set", "pcap", "filter", "function", "bpf_trace_filter")
	} else {
		_, err = k.vppctl(nodeName, "set", "trace", "filter", "function", "bpf_trace_filter")
	}
	if err != nil {
		return fmt.Errorf("failed to enable BPF filter function: %v", err)
	}

	printColored("green", "BPF filter applied successfully")
	return nil
}

// clearBPFFilter removes BPF filters from VPP
func clearBPFFilter(k *KubeClient, nodeName string, isPcap bool) error {
	// Remove the BPF filter expression (set bpf trace filter del)
	_, err := k.vppctl(nodeName, "set", "bpf", "trace", "filter", "del")
	if err != nil {
		return fmt.Errorf("failed to remove BPF filter: %v", err)
	}

	// Reset to default filter function (set trace/pcap filter function vnet_is_packet_traced)
	if isPcap {
		_, err = k.vppctl(nodeName, "set", "pcap", "filter", "function", "vnet_is_packet_traced")
	} else {
		_, err = k.vppctl(nodeName, "set", "trace", "filter", "function", "vnet_is_packet_traced")
	}
	if err != nil {
		return fmt.Errorf("failed to reset filter function: %v", err)
	}

	printColored("green", "BPF filter cleared successfully")
	return nil
}

// createCaptureLock creates a lock file for the specified node and operation
func createCaptureLock(k *KubeClient, nodeName, operation string, bpfActive bool) error {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %v", err)
	}

	lockInfo := CaptureLockInfo{
		NodeName:  nodeName,
		Operation: operation,
		StartedAt: time.Now(),
		Hostname:  hostname,
		BPFActive: bpfActive,
	}

	lockData, err := json.MarshalIndent(lockInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lock info: %v", err)
	}

	// Find the pod on the specified node
	podName, err := k.findNodePod(nodeName, defaultPod, defaultNamespace)
	if err != nil {
		return fmt.Errorf("could not find calico-vpp-node pod on node '%s': %v", nodeName, err)
	}

	// Create lock file inside VPP pod using kubectl exec
	createCmd := fmt.Sprintf("cat > %s", captureLockFile)
	_, err = k.execInPod(defaultNamespace, podName, defaultContainerVpp, "sh", "-c", createCmd)
	if err != nil {
		return fmt.Errorf("failed to create lock file in VPP pod: %v", err)
	}

	// Write the lock data to the file via stdin
	cmd := exec.Command(kubectlCmd, "exec", "-i", "-n", defaultNamespace,
		"-c", defaultContainerVpp, podName, "--", "sh", "-c", createCmd)
	cmd.Stdin = strings.NewReader(string(lockData))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to write lock file data: %v, output: %s", err, string(output))
	}

	return nil
}

// checkCaptureLock checks if there's an active capture lock and returns conflict info
func checkCaptureLock(k *KubeClient, nodeName string) (*CaptureLockInfo, error) {
	// Find the pod on the specified node
	podName, err := k.findNodePod(nodeName, defaultPod, defaultNamespace)
	if err != nil {
		return nil, fmt.Errorf("could not find calico-vpp-node pod on node '%s': %v", nodeName, err)
	}

	// Check if lock file exists in VPP pod
	checkCmd := fmt.Sprintf("test -f %s", captureLockFile)
	_, err = k.execInPod(defaultNamespace, podName, defaultContainerVpp, "sh", "-c", checkCmd)
	if err != nil {
		// Lock file doesn't exist
		return nil, nil
	}

	// Read lock file from VPP pod
	readCmd := fmt.Sprintf("cat %s", captureLockFile)
	lockData, err := k.execInPod(defaultNamespace, podName, defaultContainerVpp, "sh", "-c", readCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to read lock file from VPP pod: %v", err)
	}

	var lockInfo CaptureLockInfo
	err = json.Unmarshal([]byte(lockData), &lockInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse lock file: %v", err)
	}

	// Check if the lock is for the same node
	if lockInfo.NodeName == nodeName {
		return &lockInfo, nil
	}

	return nil, nil // Lock exists but for different node (should not happen)
}

// removeCaptureLock removes the capture lock file
func removeCaptureLock(k *KubeClient, nodeName string) error {
	// Find the pod on the specified node
	podName, err := k.findNodePod(nodeName, defaultPod, defaultNamespace)
	if err != nil {
		return fmt.Errorf("could not find calico-vpp-node pod on node '%s': %v", nodeName, err)
	}

	// Check if lock file exists in VPP pod
	checkCmd := fmt.Sprintf("test -f %s", captureLockFile)
	_, err = k.execInPod(defaultNamespace, podName, defaultContainerVpp, "sh", "-c", checkCmd)
	if err != nil {
		// Lock file doesn't exist, nothing to remove
		return nil
	}

	// Remove lock file from VPP pod
	removeCmd := fmt.Sprintf("rm -f %s", captureLockFile)
	_, err = k.execInPod(defaultNamespace, podName, defaultContainerVpp, "sh", "-c", removeCmd)
	if err != nil {
		return fmt.Errorf("failed to remove lock file from VPP pod: %v", err)
	}

	return nil
}

// captureCleanupCommand performs forced cleanup of all capture operations
func captureCleanupCommand(k *KubeClient, nodeName string) error {
	validatedNode, err := validateNodeName(k, nodeName)
	if err != nil {
		return err
	}

	printColored("blue", fmt.Sprintf("Starting cleanup on node '%s'", validatedNode))

	// Stop all active traces
	printColored("blue", "Clearing traces...")
	_, err = k.vppctl(validatedNode, "clear", "trace")
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to clear trace: %v", err))
	} else {
		printColored("green", "trace cleared")
	}

	// Stop PCAP captures
	printColored("blue", "Stopping PCAP captures...")
	_, err = k.vppctl(validatedNode, "pcap", "trace", "off")
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to stop PCAP trace: %v", err))
	} else {
		printColored("green", "PCAP trace stopped")
	}

	// Stop dispatch captures
	printColored("blue", "Stopping dispatch captures...")
	_, err = k.vppctl(validatedNode, "pcap", "dispatch", "trace", "off")
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to stop dispatch trace: %v", err))
	} else {
		printColored("green", "dispatch trace stopped")
	}

	// Clear BPF filters for both trace and pcap
	printColored("blue", "Clearing BPF filters...")
	err = clearBPFFilter(k, validatedNode, false)
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to clear trace BPF filter: %v", err))
	}
	err = clearBPFFilter(k, validatedNode, true)
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to clear PCAP BPF filter: %v", err))
	}

	// Remove lock file
	printColored("blue", "Removing lock file...")
	err = removeCaptureLock(k, validatedNode)
	if err != nil {
		printColored("red", fmt.Sprintf("Warning: Failed to remove lock file: %v", err))
	} else {
		printColored("green", "lock file removed")
	}

	printColored("green", "Cleanup completed")
	return nil
}
