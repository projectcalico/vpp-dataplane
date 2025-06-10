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
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	sudoCmd     = "sudo"
	dockerCmd   = "docker"

	// Command templates
	cmdVppHardInt = "show hardware-interfaces"
	cmdVppShowRun = "show run"
	cmdVppShowErr = "show err"

	// Kubernetes client timeout
	kubeClientTimeout = 15 * time.Second
)

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

		// Get CAPO policies
		capoCmds := []CommandSpec{
			{"show capo interfaces", node + ".show-capo-interfaces"},
			{"show capo policies verbose", node + ".show-capo-policies"},
			{"show capo rules", node + ".show-capo-rules"},
			{"show capo ipsets", node + ".show-capo-ipsets"},
		}
		executeVppCommandGroup(k, exportDir, prefix, node, "Dumping node policies", capoCmds)
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
	fmt.Println("calicovppctl export                                                   - Create an archive with vpp & k8 system state for debugging")
	fmt.Println("calicovppctl exportnode [-node NODENAME]                              - Create an archive with vpp & k8 system state for a specific node")
	fmt.Println("calicovppctl gdb                                                      - Attach gdb to the running vpp on the current machine")
	fmt.Println("calicovppctl sh [-component vpp|agent] [-node NODENAME]               - Get a shell in vpp (dataplane) or agent (controlplane) container")
	fmt.Println()
}

func main() {
	// Define global flags
	var (
		nodeName  = flag.String("node", "", "Node name to operate on")
		component = flag.String("component", "", "Component to operate on (vpp, agent, felix)")
		follow    = flag.Bool("f", false, "Follow logs (for log command)")
		help      = flag.Bool("help", false, "Show help message")
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
			case "vppctl", "log", "clear", "export", "exportnode", "gdb", "sh":
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
	helpPtr := flagSet.Bool("help", false, "Show help message")

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
			case "-f":
				*followPtr = true
			case "-help", "--help", "-h":
				*helpPtr = true
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
	*help = *helpPtr

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
