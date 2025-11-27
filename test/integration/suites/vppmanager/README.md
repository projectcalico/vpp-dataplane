# VPP Manager Tests

Functional tests for vpp-manager uplink configuration components.

## Tests

- **uplink_test.go** - Uplink interface configuration (AF_PACKET, TAP, VRF)

## Running

```bash
cd test/integration/suites/vppmanager
VPP_IMAGE=calicovpp/vpp:latest VPP_BINARY=/usr/bin/vpp go test -v
```
vppctl show ip6 mfib ff02::1:2
vppctl show errors
vppctl show punt
```

## Running Tests

### Prerequisites

Set environment variables:
```bash
export VPP_IMAGE="calicovpp/vpp:latest"
export VPP_BINARY="/usr/bin/vpp"
```

### Run All Tests

```bash
go test -v ./test/integration/suites/vppmanager/...
```

### Run Only DHCP Tests

```bash
go test -v ./test/integration/suites/vppmanager/... -run "DHCP"
```

### Run Specific Test Cases

```bash
# DHCPv4 only
go test -v ./test/integration/suites/vppmanager/... -run "DHCPv4"

# DHCPv6 only (will fail - documents the issue)
go test -v ./test/integration/suites/vppmanager/... -run "DHCPv6"
```

## Test Architecture

### DHCP Server Fixture

Tests use `framework.DHCPServerFixture` which provides:
- DHCPv4 server using dnsmasq
- DHCPv6 server using dnsmasq with RA
- Network connectivity to VPP container
- Configurable address pools, gateways, DNS servers

**Example:**
```go
dhcpServer := &framework.DHCPServerFixture{
    Version:     4, // 4 for DHCPv4, 6 for DHCPv6
    NetworkCIDR: "192.168.10.0/24",
    ServerIP:    "192.168.10.1",
    RangeStart:  "192.168.10.100",
    RangeEnd:    "192.168.10.200",
    Gateway:     "192.168.10.1",
    DNSServers:  []string{"8.8.8.8"},
    LeaseTime:   "1h",
}
err := dhcpServer.Setup(testCtx.Log)
```

### VPP Uplink Configuration

Tests create TAP uplink interfaces using `framework.VppFixture`:
```go
uplinkConfig := &framework.UplinkConfig{
    InterfaceName: "dhcp-uplink",
    MTU:           1500,
}
swIfIndex, err := vppFixture.Instance.ConfigureUplink(uplinkConfig)
```

## Expected Results

| Test | Expected Result | Reason |
|------|-----------------|---------|
| DHCPv4 Address Acquisition | ✓ PASS | DHCPv4 works correctly |
| DHCPv4 DISCOVER Handling | ✓ PASS | VPP punts DHCP packets to host |
| DHCPv6 Solicitation | ✗ FAIL | IPv6 mfib RPF drops packets |
| DHCPv6 Documentation | ✓ PASS | Documents the known issue |

## Workarounds for DHCPv6 Issue

### Option 1: Use Router Advertisement (RA)
Instead of `WithoutRA=solicit`, let DHCPv6 wait for RA:
```ini
[Network]
DHCP=ipv6
# Don't set WithoutRA=solicit
```

### Option 2: Disable mfib RPF Check
Configure VPP to disable RPF checking for the multicast group:
```bash
vppctl ip mfib route add ff02::1:2/128 via local Forward
```

### Option 3: Use Static IPv6 Configuration
Avoid DHCP entirely for IPv6:
```ini
[Network]
Address=fd00:1234::10/64
Gateway=fd00:1234::1
```

## Implementation References

- **VPP Manager Main**: `vpp-manager/main.go`
- **VPP Runner**: `vpp-manager/vpp_runner.go`
- **Uplink Configuration**: `vpp-manager/uplink/common.go`
- **Uplink Drivers**: `vpp-manager/uplink/*.go`
- **Test Framework**: `test/integration/framework/`

## Related Documentation

- VPP multicast documentation: https://wiki.fd.io/view/VPP/Multicast_FIB
- DHCPv6 RFC: https://www.rfc-editor.org/rfc/rfc8415
- systemd-networkd DHCP: https://www.freedesktop.org/software/systemd/man/systemd.network.html

## Future Improvements

1. **Complete Network Plumbing**: Currently `DHCPServerFixture.ConnectToVpp()` is a stub. Need to implement full veth pair creation and network namespace management.

2. **Use CoreDHCP**: Switch from dnsmasq to coredhcp (github.com/coredhcp/coredhcp) for more control and better DHCPv6 testing.

3. **Fix DHCPv6 mfib Issue**: Work with VPP community to find proper solution for mfib RPF with DHCPv6 solicitations.

4. **Add More Scenarios**: Test DHCP renewal, rebinding, release, etc.

5. **Packet Capture**: Add tcpdump/wireshark packet capture to verify DHCP message flow.

## Troubleshooting

### DHCP server container fails to start
```bash
# Check if port 67/68 (DHCPv4) or 547/546 (DHCPv6) are in use
netstat -uln | grep -E '67|68|546|547'

# Check Docker logs
docker logs test-dhcpv4-<random>
docker logs test-dhcpv6-<random>
```

### VPP not punting DHCP packets
```bash
# Check punt configuration
vppctl show punt

# Check if tap interface is up
vppctl show interface

# Check if interface has IP address
vppctl show interface address
```

### DHCPv6 solicitations not visible
```bash
# Capture on VPP side
vppctl packet trace add af-packet-input 100
vppctl packet trace dump

# Check mfib drops
vppctl show errors | grep mfib
```
