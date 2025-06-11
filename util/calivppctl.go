package main

import (
    "archive/tar"
    "bufio"
    "compress/gzip"
    "context"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
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
    kubectlCmd           = "kubectl"
    bashCmd              = "bash"
    vppctlPath           = "/usr/bin/vppctl"
    vppSockPath          = "/var/run/vpp/cli.sock"
    sudoCmd              = "sudo"
    dockerCmd            = "docker"
    
    // Export directory and file constants
    defaultExportDir     = "./export"
    exportTarFile        = "./export.tar.gz"
    
    // Command templates
    cmdKubeVersion       = "version"
    cmdGetPodsWide       = "get pods -o wide -A"
    cmdGetServicesWide   = "get services -o wide -A"
    cmdGetNodesWide      = "get nodes -o wide"
    cmdGetInstallYaml    = "get installation -o yaml"
    cmdVppHardInt        = "show hardware-interfaces"
    cmdVppShowRun        = "show run"
    cmdVppShowErr        = "show err"
)

// Terminal colors
var (
    green   = "\033[0;32m"
    red     = "\033[0;31m"
    blue    = "\033[0;34m"
    grey    = "\033[0;37m"
    resetC  = "\033[0m"
)

type KubeClient struct {
    clientset *kubernetes.Clientset
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
    
    return &KubeClient{clientset: clientset}, nil
}

func (k *KubeClient) getAvailableNodeNames() ([]string, error) {
    nodes, err := k.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
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
    pods, err := k.clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
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
    args := []string{"logs", "-n", namespace}
    if follow {
        args = append(args, "-f")
    }
    if containerName != "" {
        args = append(args, "-c", containerName)
    }
    args = append(args, podName)
    
    cmd := exec.Command(kubectlCmd, args...)
    output, err := cmd.CombinedOutput()
    return string(output), err
}

func (k *KubeClient) vppctl(nodeName string, args ...string) (string, error) {
    podName, err := k.findNodePod(nodeName, defaultPod, defaultNamespace)
    if err != nil {
        return "", err
    }
    
    vppCtlArgs := append([]string{vppctlPath, "-s", vppSockPath}, args...)
    return k.execInPod(defaultNamespace, podName, defaultContainerVpp, vppCtlArgs...)
}

func printColored(color, message string) {
    fmt.Printf("%s%s%s\n", color, message, resetC)
}

func printColoredDot(color string) {
    fmt.Printf("%s.%s", color, resetC)
}

func handleError(err error, message string) {
    if err != nil {
        printColored(red, fmt.Sprintf("%s: %v", message, err))
        os.Exit(1)
    }
}

func kubectlCommand(args ...string) (string, error) {
    cmd := exec.Command(kubectlCmd, args...)
    output, err := cmd.CombinedOutput()
    return string(output), err
}

func runInteractiveCommand(command string, args ...string) error {
    cmd := exec.Command(command, args...)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
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

// KubeCommandGroup represents a group of kubectl commands to execute
type KubeCommandGroup struct {
    Description string
    Commands    []KubeCommand
}

// KubeCommand defines a kubectl command and its output file
type KubeCommand struct {
    Args    []string
    OutFile string
}

// CommandSpec defines a command and its output file
type CommandSpec struct {
    cmd  string
    file string
}

// runCommandAndWriteToFile executes a command and writes output to a file
func runCommandAndWriteToFile(writeToFile func(string, string) error, command string, args []string, outFile string) {
    cmd := exec.Command(command, args...)
    output, _ := cmd.CombinedOutput()
    writeToFile(outFile, string(output))
    printColoredDot(grey)
}

// runVppctlCommandAndWriteToFile executes a VPP command and writes output to a file
func runVppctlCommandAndWriteToFile(k *KubeClient, writeToFile func(string, string) error, node string, cmdSpec CommandSpec) {
    output, _ := k.vppctl(node, strings.Split(cmdSpec.cmd, " ")...)
    writeToFile(cmdSpec.file, output)
    printColoredDot(grey)
}

// executeCommandGroup executes a group of kubectl commands and writes outputs to files
func executeCommandGroup(writeToFile func(string, string) error, group KubeCommandGroup) {
    printColored(grey, group.Description)
    for _, cmd := range group.Commands {
        runCommandAndWriteToFile(writeToFile, kubectlCmd, cmd.Args, cmd.OutFile)
    }
    fmt.Println()
}

// executeVppCommandGroup executes a group of VPP commands on a node and writes outputs to files
func executeVppCommandGroup(k *KubeClient, writeToFile func(string, string) error, node string, description string, cmds []CommandSpec) {
    printColored(grey, fmt.Sprintf("%s '%s'", description, node))
    for _, c := range cmds {
        runVppctlCommandAndWriteToFile(k, writeToFile, node, c)
    }
    fmt.Println()
}

// validateNodeAndFindPod validates node name and finds the pod on that node
func validateNodeAndFindPod(k *KubeClient, nodeName, podPrefix, namespace string) (string, string, error) {
    validatedNode, err := validateNodeName(k, nodeName)
    if err != nil {
        return "", "", err
    }
    
    podName, err := k.findNodePod(validatedNode, podPrefix, namespace)
    if err != nil {
        return "", "", err
    }
    
    return validatedNode, podName, nil
}

func exportData(k *KubeClient, exportDir, prefix string, nodeName string) error {
    if exportDir == "" {
        exportDir = defaultExportDir
    }
    
    printColored(green, fmt.Sprintf("Exporting to %s", exportDir))
    if err := os.MkdirAll(exportDir, 0755); err != nil {
        return err
    }
    
    // Helper function to write command output to file
    writeToFile := func(file string, data string) error {
        f, err := os.Create(filepath.Join(exportDir, prefix+file))
        if err != nil {
            return err
        }
        defer f.Close()
        _, err = f.WriteString(data)
        return err
    }
    
    // Collect Kubernetes data
    printColored(grey, "Logging k8s internals")
    
    // Define common kubectl commands
    k8sCommands := KubeCommandGroup{
        Description: "Collecting Kubernetes data",
        Commands: []KubeCommand{
            {[]string{"version"}, "kubectl-version"},
            {[]string{"get", "pods", "-o", "wide", "-A"}, "get-pods"},
            {[]string{"get", "services", "-o", "wide", "-A"}, "get-services"},
            {[]string{"get", "nodes", "-o", "wide"}, "get-nodes"},
            {[]string{"get", "installation", "-o", "yaml"}, "installation.yaml"},
            {[]string{"-n", "calico-system", "get", "configmap", "cni-config", "-o", "yaml"}, "cni-config.configmap.yaml"},
            {[]string{"-n", "calico-vpp-dataplane", "get", "daemonset", "calico-vpp-node", "-o", "yaml"}, "calico-vpp-node.daemonset.yaml"},
            {[]string{"-n", "calico-vpp-dataplane", "get", "configmap", "calico-vpp-config", "-o", "yaml"}, "calico-vpp-config.configmap.yaml"},
        },
    }
    
    // Execute kubectl commands
    for _, cmd := range k8sCommands.Commands {
        runCommandAndWriteToFile(writeToFile, kubectlCmd, cmd.Args, cmd.OutFile)
    }
    
    // Journalctl kubelet logs (uses sudo, not kubectl)
    runCommandAndWriteToFile(writeToFile, sudoCmd, []string{"journalctl", "-u", "kubelet", "-r", "-n200"}, "kubelet-journal")
    
    // Get calico-vpp-config
    runCommandAndWriteToFile(writeToFile, kubectlCmd, []string{"-n", "calico-vpp-dataplane", "get", "configmap", "calico-vpp-config", "-o", "yaml"}, "calico-vpp-config.configmap.yaml")
    
    // Get operator logs
    operatorPods, err := k.clientset.CoreV1().Pods(operatorNamespace).List(context.TODO(), metav1.ListOptions{})
    if err == nil && len(operatorPods.Items) > 0 {
        operatorPodName := operatorPods.Items[0].Name
        logs, _ := k.getPodLogs(operatorNamespace, operatorPodName, "", false)
        writeToFile("operator.log", logs)
    }
    printColoredDot(grey)
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
        executeVppCommandGroup(k, writeToFile, node, "Dumping node stats", vppStatCmds)
        
        // Get Calico logs
        calicoPodName, err := k.findNodePod(node, defaultCalicoPod, calicoSystemNS)
        if err == nil {
            printColored(grey, fmt.Sprintf("Dumping node '%s' calico logs", node))
            // Describe calico-node pod
            runCommandAndWriteToFile(writeToFile, kubectlCmd, []string{"-n", calicoSystemNS, "describe", "pod/" + calicoPodName}, node+".describe-calico-node-pod")
            
            // Get calico-node logs
            logs, _ := k.getPodLogs(calicoSystemNS, calicoPodName, defaultCalicoSvcCont, false)
            writeToFile(node+".calico-node.log", logs)
            printColoredDot(grey)
        }
        fmt.Println()
        
        // Get VPP logs
        printColored(grey, fmt.Sprintf("Dumping node '%s' vpp logs", node))
        vppPodName, err := k.findNodePod(node, defaultPod, defaultNamespace)
        if err == nil {
            // Describe VPP pod
            runCommandAndWriteToFile(writeToFile, kubectlCmd, []string{"-n", defaultNamespace, "describe", "pod/" + vppPodName}, node+".describe-vpp-pod")
            
            // Get VPP container logs
            vppLogs, _ := k.getPodLogs(defaultNamespace, vppPodName, defaultContainerVpp, false)
            writeToFile(node+".vpp.log", vppLogs)
            printColoredDot(grey)

            // Get Agent container logs
            agentLogs, _ := k.getPodLogs(defaultNamespace, vppPodName, defaultContainerAgt, false)
            writeToFile(node+".agent.log", agentLogs)
            printColoredDot(grey)
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
        executeVppCommandGroup(k, writeToFile, node, "Dumping node state", cnatCmds)
        
        // Get CAPO policies
        capoCmds := []CommandSpec{
            {"show capo interfaces", node + ".show-capo-interfaces"},
            {"show capo policies verbose", node + ".show-capo-policies"},
            {"show capo rules", node + ".show-capo-rules"},
            {"show capo ipsets", node + ".show-capo-ipsets"},
        }
        executeVppCommandGroup(k, writeToFile, node, "Dumping node policies", capoCmds)
    }
    
    // Compress if default export dir
    if exportDir == defaultExportDir {
        printColored(grey, "Compressing...")
        err := createTarGz(exportDir, exportTarFile)
        if err != nil {
            return err
        }
        
        os.RemoveAll(exportDir)
        printColored(green, fmt.Sprintf("Done exporting to %s", exportTarFile))
    } else {
        printColored(green, fmt.Sprintf("Done exporting to %s", exportDir))
    }
    
    return nil
}

func clearVppStats(k *KubeClient) error {
    nodeNames, err := k.getAvailableNodeNames()
    if err != nil {
        return err
    }
    
    for _, node := range nodeNames {
        k.vppctl(node, "clear", "run")
        k.vppctl(node, "clear", "err")
    }
    
    return nil
}

func printLogs(k *KubeClient, nodeName string, component string, follow bool) error {
    validatedNode, err := validateNodeName(k, nodeName)
    if err != nil {
        return err
    }
    
    if component == "" || component == "all" {
        printColored(blue, "----- Felix -----")
        felixPod, err := k.findNodePod(validatedNode, defaultCalicoPod, calicoSystemNS)
        if err == nil {
            logs, _ := getPodLogsFiltered(k, calicoSystemNS, felixPod, "", false,
                func(line string) bool {
                    return !strings.Contains(line, "time=")
                })
            fmt.Println(logs)
        }
        
        printColored(blue, "----- VPP Manager -----")
        vppPod, err := k.findNodePod(validatedNode, defaultPod, defaultNamespace)
        if err == nil {
            logs, _ := k.getPodLogs(defaultNamespace, vppPod, defaultContainerVpp, false)
            fmt.Println(logs)
        }
        
        printColored(blue, "----- Calico-VPP agent -----")
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
        printColored(grey, "This shell lives inside the vpp container")
        printColored(grey, "You will find vpp-manager & vpp running")
        
    case "agent":
        containerName = defaultContainerAgt
        printColored(grey, "This shell lives inside the agent container")
        printColored(grey, "You will find calico-vpp-agent & felix running")
        
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
    fmt.Println("calivppctl vppctl [NODENAME]                        - Get a vppctl shell on a specific node")
    fmt.Println("calivppctl log [-f] [-vpp|-agent|-felix] [NODENAME] - Get the logs of vpp (dataplane) or agent (controlplane) or felix daemon")
    fmt.Println("calivppctl clear                                    - Clear vpp internal stats")
    fmt.Println("calivppctl export                                   - Create an archive with vpp & k8 system state for debugging")
    fmt.Println("                                                      It accepts a dir name and a prefix 'export [dir] [prefix]'")
    fmt.Println("calivppctl exportnode [NODENAME]                    - Create an archive with vpp & k8 system state for a specific node")
    fmt.Println("                                                      It accepts a dir name and a prefix 'exportnode NODENAME [dir] [prefix]'")
    fmt.Println("calivppctl gdb                                      - Attach a gdb to the running vpp on the current machine")
    fmt.Println("calivppctl sh [vpp|agent] [NODENAME]                - Get a shell in vpp (dataplane) or agent (controlplane) container")
}

func runShellCommand(name string, args ...string) error {
    cmd := exec.Command(name, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Stdin = os.Stdin
    return cmd.Run()
}

func main() {
    if len(os.Args) < 2 {
        printHelp()
        os.Exit(1)
    }
    
    k, err := newKubeClient()
    if err != nil {
        handleError(err, "Failed to create Kubernetes client")
    }
    
    command := os.Args[1]
    args := os.Args[2:]
    
    switch command {
    case "vppctl":
        nodeName := ""
        vppctlArgs := []string{}
        
        if len(args) > 0 {
            nodeName = args[0]
            vppctlArgs = args[1:]
        }
        
        validatedNode, err := validateNodeName(k, nodeName)
        if err != nil {
            handleError(err, "Node validation failed")
        }
        
        // If no additional arguments, start interactive mode
        if len(vppctlArgs) == 0 {
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
            // Execute single command mode (existing behavior)
            output, err := k.vppctl(validatedNode, vppctlArgs...)
            if err != nil {
                handleError(err, "vppctl failed")
            }
            fmt.Println(output)
        }
        
    case "log":
        var nodeName string
        var component string
        follow := false
        
        for i := 0; i < len(args); i++ {
            switch args[i] {
            case "-f":
                follow = true
            case "-vpp":
                component = "vpp"
            case "-agent":
                component = "agent"
            case "-felix":
                component = "felix"
            default:
                nodeName = args[i]
            }
        }
        
        err := printLogs(k, nodeName, component, follow)
        if err != nil {
            handleError(err, "Failed to print logs")
        }
        
    case "clear":
        err := clearVppStats(k)
        if err != nil {
            handleError(err, "Failed to clear stats")
        }
        
    case "export":
        dir := defaultExportDir
        prefix := ""
        
        if len(args) > 0 {
            dir = args[0]
        }
        if len(args) > 1 {
            prefix = args[1]
        }
        
        err := exportData(k, dir, prefix, "")
        if err != nil {
            handleError(err, "Export failed")
        }
        
    case "exportnode":
        if len(args) < 1 {
            handleError(fmt.Errorf("missing node name for exportnode command"), "")
        }
        
        nodeName := args[0]
        validatedNode, err := validateNodeName(k, nodeName)
        if err != nil {
            handleError(err, "Node validation failed")
        }
        
        dir := defaultExportDir
        prefix := ""
        
        if len(args) > 1 {
            dir = args[1]
        }
        if len(args) > 2 {
            prefix = args[2]
        }
        
        err = exportData(k, dir, prefix, validatedNode)
        if err != nil {
            handleError(err, "Export failed")
        }
        
    case "gdb":
        // Find the VPP docker container
        printColored(grey, "This finds the VPP running in a vpp_calico-vpp docker container")
        printColored(grey, "and attaches to it. [Ctrl+C detach q ENTER] to exit")
        
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
        if len(args) < 1 {
            handleError(fmt.Errorf("missing component. Use 'vpp' or 'agent'"), "Use 'vpp' or 'agent'")
        }
        
        component := args[0]
        nodeName := ""
        if len(args) > 1 {
            nodeName = args[1]
        }
        
        err := getShell(k, component, nodeName)
        if err != nil {
            handleError(err, "Shell failed")
        }
            
    default:
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