
function generate_trex_conf () {
echo "---
- port_limit: 2
  version: 2
  interfaces: ['--vdev=net_memif,role=client,socket=vpp/memif,socket-abstract=yes,zero-copy=no', 'dummy']
  c: 4
  port_info:
      - dest_mac: 02:00:00:00:00:02
        src_mac:  02:00:00:00:00:01
  platform:
      master_thread_id: 15
      latency_thread_id: 16
      dual_if:
          - socket: 0
            threads: [17, 18, 19, 20]
          - socket: 1
            threads: [21, 22, 23, 36]
" > /etc/trex_cfg.yaml
}

generate_trex_conf
trex -i $@

