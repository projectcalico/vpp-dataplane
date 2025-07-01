// Copyright (C) 2019 Cisco Systems Inc.
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

package prometheus

func getVppIfStatDescription(vppStatName string) string {
	switch cleanVppIfStatName(vppStatName) {
	case "drops":
		return "number of drops on interface"
	case "ip4":
		return "IPv4 received packets"
	case "ip6":
		return "IPv6 received packets"
	case "punt":
		return "number of punts on interface"
	case "rx_bytes":
		return "total number of bytes received over the interface"
	case "tx_bytes":
		return "total number of bytes transmitted by the interface"
	case "rx_packets":
		return "total number of packets received over the interface"
	case "tx_packets":
		return "total number of packets transmitted by the interface"
	case "tx_broadcast_packets":
		return "number of multipoint communications transmitted by the interface in packets"
	case "rx_broadcast_packets":
		return "number of multipoint communications received by the interface in packets"
	case "tx_broadcast_bytes":
		return "number of multipoint communications transmitted by the interface in bytes"
	case "rx_broadcast_bytes":
		return "number of multipoint communications received by the interface in bytes"
	case "tx_unicast_packets":
		return "number of point-to-point communications transmitted by the interface in packets"
	case "rx_unicast_packets":
		return "number of point-to-point communications received by the interface in packets"
	case "tx_unicast_bytes":
		return "number of point-to-point communications transmitted by the interface in bytes"
	case "rx_unicast_bytes":
		return "number of point-to-point communications received by the interface in bytes"
	case "tx_multicast_packets":
		return "number of one-to-many communications transmitted by the interface in packets"
	case "rx_multicast_packets":
		return "number of one-to-many communications received by the interface in packets"
	case "tx_multicast_bytes":
		return "number of one-to-many communications transmitted by the interface in bytes"
	case "rx_multicast_bytes":
		return "number of one-to-many communications received by the interface in bytes"
	case "rx_error":
		return "total number of erroneous received packets"
	case "tx_error":
		return "total number of erroneous transmitted packets"
	case "rx_miss":
		return "total of rx packets dropped because there are no available buffer"
	case "tx_miss":
		return "total of tx packets dropped because there are no available buffer"
	case "rx_no_buf":
		return "total number of rx mbuf allocation failures"
	case "tx_no_buf":
		return "total number of tx mbuf allocation failures"
	default:
		return vppStatName
	}
}

func getVppTCPStatDescription(vppStatName string) string {
	switch vppStatName {
	// /sys/tcp/... stats
	case "tcp_timer_expirations":
		return "number of TCP timer expirations"
	case "tcp_rxt_segs":
		return "number of TCP retransmitted segments"
	case "tcp_tr_events":
		return "number of TCP timer/retransmit events"
	case "tcp_to_establish":
		return "number of TCP timeouts in establish state"
	case "tcp_to_persist":
		return "number of TCP timeouts in persist state"
	case "tcp_to_closewait":
		return "number of TCP timeouts in close-wait state"
	case "tcp_to_closewait2":
		return "number of TCP timeouts in close-wait2 state"
	case "tcp_to_finwait1":
		return "number of TCP timeouts in fin-wait1 state"
	case "tcp_to_finwait2":
		return "number of TCP timeouts in fin-wait2 state"
	case "tcp_to_lastack":
		return "number of TCP timeouts in last-ack state"
	case "tcp_to_closing":
		return "number of TCP timeouts in closing state"
	case "tcp_tr_abort":
		return "number of TCP timer/retransmit aborts"
	case "tcp_rst_unread":
		return "number of TCP resets on unread data"
	case "tcp_no_buffer":
		return "number of TCP events with no buffer available"
	// /err/tcp4/... stats
	case "tcp4_drop_ack_dup":
		return "number of TCP4 dropped duplicate ACK packets"
	case "tcp4_drop_ack_future":
		return "number of TCP4 dropped future ACK packets"
	case "tcp4_drop_ack_invalid":
		return "number of TCP4 dropped invalid ACK packets"
	case "tcp4_drop_ack_ok":
		return "number of TCP4 dropped valid ACK packets"
	case "tcp4_drop_ack_old":
		return "number of TCP4 dropped old ACK packets"
	case "tcp4_drop_conn_accepted":
		return "number of TCP4 dropped connection accepted packets"
	case "tcp4_drop_connection_closed":
		return "number of TCP4 dropped connection closed packets"
	case "tcp4_drop_create_exists":
		return "number of TCP4 dropped create exists packets"
	case "tcp4_drop_create_session_fail":
		return "number of TCP4 dropped create session fail packets"
	case "tcp4_drop_dispatch":
		return "number of TCP4 dropped dispatch packets"
	case "tcp4_drop_enqueued":
		return "number of TCP4 dropped enqueued packets"
	case "tcp4_drop_enqueued_ooo":
		return "number of TCP4 dropped out-of-order enqueued packets"
	case "tcp4_drop_fifo_full":
		return "number of TCP4 dropped packets due to full FIFO"
	case "tcp4_drop_filtered":
		return "number of TCP4 dropped filtered packets"
	case "tcp4_drop_fin_rcvd":
		return "number of TCP4 dropped FIN received packets"
	case "tcp4_drop_invalid_connection":
		return "number of TCP4 dropped invalid connection packets"
	case "tcp4_drop_length":
		return "number of TCP4 dropped length error packets"
	case "tcp4_drop_link_local_rw":
		return "number of TCP4 dropped link local read/write packets"
	case "tcp4_drop_lookup_drops":
		return "number of TCP4 dropped lookup drops packets"
	case "tcp4_drop_msg_queue_full":
		return "number of TCP4 dropped packets due to full message queue"
	case "tcp4_drop_no_listener":
		return "number of TCP4 dropped no listener packets"
	case "tcp4_drop_none":
		return "number of TCP4 dropped none packets"
	case "tcp4_drop_options":
		return "number of TCP4 dropped options packets"
	case "tcp4_drop_partially_enqueued":
		return "number of TCP4 dropped partially enqueued packets"
	case "tcp4_drop_paws":
		return "number of TCP4 dropped PAWS packets"
	case "tcp4_drop_pkts_sent":
		return "number of TCP4 dropped packets sent"
	case "tcp4_drop_punt":
		return "number of TCP4 dropped punt packets"
	case "tcp4_drop_rcv_wnd":
		return "number of TCP4 dropped receive window packets"
	case "tcp4_drop_rst_rcvd":
		return "number of TCP4 dropped RST received packets"
	case "tcp4_drop_rst_sent":
		return "number of TCP4 dropped RST sent packets"
	case "tcp4_drop_segment_invalid":
		return "number of TCP4 dropped invalid segment packets"
	case "tcp4_drop_segment_old":
		return "number of TCP4 dropped old segment packets"
	case "tcp4_drop_spurious_syn":
		return "number of TCP4 dropped spurious SYN packets"
	case "tcp4_drop_spurious_syn_ack":
		return "number of TCP4 dropped spurious SYN-ACK packets"
	case "tcp4_drop_syn_acks_rcvd":
		return "number of TCP4 dropped SYN-ACK received packets"
	case "tcp4_drop_syns_rcvd":
		return "number of TCP4 dropped SYN received packets"
	case "tcp4_drop_wrong_thread":
		return "number of TCP4 dropped wrong thread packets"
	case "tcp4_drop_zero_rwnd":
		return "number of TCP4 dropped zero receive window packets"
	case "tcp4_established_ack_dup":
		return "number of TCP4 established duplicate ACK packets"
	case "tcp4_established_ack_future":
		return "number of TCP4 established future ACK packets"
	case "tcp4_established_ack_invalid":
		return "number of TCP4 established invalid ACK packets"
	case "tcp4_established_ack_ok":
		return "number of TCP4 established valid ACK packets"
	case "tcp4_established_ack_old":
		return "number of TCP4 established old ACK packets"
	case "tcp4_established_conn_accepted":
		return "number of TCP4 established connection accepted packets"
	case "tcp4_established_connection_closed":
		return "number of TCP4 established connection closed packets"
	case "tcp4_established_create_exists":
		return "number of TCP4 established create exists packets"
	case "tcp4_established_create_session_fail":
		return "number of TCP4 established create session fail packets"
	case "tcp4_established_dispatch":
		return "number of TCP4 established dispatch packets"
	case "tcp4_established_enqueued":
		return "number of TCP4 established enqueued packets"
	case "tcp4_established_enqueued_ooo":
		return "number of TCP4 established out-of-order enqueued packets"
	case "tcp4_established_fifo_full":
		return "number of TCP4 established packets dropped due to full FIFO"
	case "tcp4_established_filtered":
		return "number of TCP4 established filtered packets"
	case "tcp4_established_fin_rcvd":
		return "number of TCP4 established FIN received packets"
	case "tcp4_established_invalid_connection":
		return "number of TCP4 established invalid connection packets"
	case "tcp4_established_length":
		return "number of TCP4 established length error packets"
	case "tcp4_established_link_local_rw":
		return "number of TCP4 established link local read/write packets"
	case "tcp4_established_lookup_drops":
		return "number of TCP4 established lookup drops packets"
	case "tcp4_established_msg_queue_full":
		return "number of TCP4 established packets dropped due to full message queue"
	case "tcp4_established_no_listener":
		return "number of TCP4 established no listener packets"
	case "tcp4_established_none":
		return "number of TCP4 established none packets"
	case "tcp4_established_options":
		return "number of TCP4 established options packets"
	case "tcp4_established_partially_enqueued":
		return "number of TCP4 established partially enqueued packets"
	case "tcp4_established_paws":
		return "number of TCP4 established PAWS packets"
	case "tcp4_established_pkts_sent":
		return "number of TCP4 established packets sent"
	case "tcp4_established_punt":
		return "number of TCP4 established punt packets"
	case "tcp4_established_rcv_wnd":
		return "number of TCP4 established receive window packets"
	case "tcp4_established_rst_rcvd":
		return "number of TCP4 established RST received packets"
	case "tcp4_established_rst_sent":
		return "number of TCP4 established RST sent packets"
	case "tcp4_established_segment_invalid":
		return "number of TCP4 established invalid segment packets"
	case "tcp4_established_segment_old":
		return "number of TCP4 established old segment packets"
	case "tcp4_established_spurious_syn":
		return "number of TCP4 established spurious SYN packets"
	case "tcp4_established_spurious_syn_ack":
		return "number of TCP4 established spurious SYN-ACK packets"
	case "tcp4_established_syn_acks_rcvd":
		return "number of TCP4 established SYN-ACK received packets"
	case "tcp4_established_syns_rcvd":
		return "number of TCP4 established SYN received packets"
	case "tcp4_established_wrong_thread":
		return "number of TCP4 established wrong thread packets"
	case "tcp4_established_zero_rwnd":
		return "number of TCP4 established zero receive window packets"
	case "tcp4_input_ack_dup":
		return "number of TCP4 input duplicate ACK packets"
	case "tcp4_input_ack_future":
		return "number of TCP4 input future ACK packets"
	case "tcp4_input_ack_invalid":
		return "number of TCP4 input invalid ACK packets"
	case "tcp4_input_ack_ok":
		return "number of TCP4 input valid ACK packets"
	case "tcp4_input_ack_old":
		return "number of TCP4 input old ACK packets"
	case "tcp4_input_conn_accepted":
		return "number of TCP4 input connection accepted packets"
	case "tcp4_input_connection_closed":
		return "number of TCP4 input connection closed packets"
	case "tcp4_input_create_exists":
		return "number of TCP4 input create exists packets"
	case "tcp4_input_create_session_fail":
		return "number of TCP4 input create session fail packets"
	case "tcp4_input_dispatch":
		return "number of TCP4 input dispatch packets"
	case "tcp4_input_enqueued":
		return "number of TCP4 input enqueued packets"
	case "tcp4_input_enqueued_ooo":
		return "number of TCP4 input out-of-order enqueued packets"
	case "tcp4_input_fifo_full":
		return "number of TCP4 input packets dropped due to full FIFO"
	case "tcp4_input_filtered":
		return "number of TCP4 input filtered packets"
	case "tcp4_input_fin_rcvd":
		return "number of TCP4 input FIN received packets"
	case "tcp4_input_invalid_connection":
		return "number of TCP4 input invalid connection packets"
	case "tcp4_input_length":
		return "number of TCP4 input length error packets"
	case "tcp4_input_link_local_rw":
		return "number of TCP4 input link local read/write packets"
	case "tcp4_input_lookup_drops":
		return "number of TCP4 input lookup drops packets"
	case "tcp4_input_msg_queue_full":
		return "number of TCP4 input packets dropped due to full message queue"
	case "tcp4_input_no_listener":
		return "number of TCP4 input no listener packets"
	case "tcp4_input_nolookup_ack_dup":
		return "number of TCP4 input no-lookup duplicate ACK packets"
	case "tcp4_input_nolookup_ack_future":
		return "number of TCP4 input no-lookup future ACK packets"
	case "tcp4_input_nolookup_ack_invalid":
		return "number of TCP4 input no-lookup invalid ACK packets"
	case "tcp4_input_nolookup_ack_ok":
		return "number of TCP4 input no-lookup valid ACK packets"
	case "tcp4_input_nolookup_ack_old":
		return "number of TCP4 input no-lookup old ACK packets"
	case "tcp4_input_nolookup_conn_accepted":
		return "number of TCP4 input no-lookup connection accepted packets"
	case "tcp4_input_nolookup_connection_closed":
		return "number of TCP4 input no-lookup connection closed packets"
	case "tcp4_input_nolookup_create_exists":
		return "number of TCP4 input no-lookup create exists packets"
	case "tcp4_input_nolookup_create_session_fail":
		return "number of TCP4 input no-lookup create session fail packets"
	case "tcp4_input_nolookup_dispatch":
		return "number of TCP4 input no-lookup dispatch packets"
	case "tcp4_input_nolookup_enqueued":
		return "number of TCP4 input no-lookup enqueued packets"
	case "tcp4_input_nolookup_enqueued_ooo":
		return "number of TCP4 input no-lookup out-of-order enqueued packets"
	case "tcp4_input_nolookup_fifo_full":
		return "number of TCP4 input no-lookup packets dropped due to full FIFO"
	case "tcp4_input_nolookup_filtered":
		return "number of TCP4 input no-lookup filtered packets"
	case "tcp4_input_nolookup_fin_rcvd":
		return "number of TCP4 input no-lookup FIN received packets"
	case "tcp4_input_nolookup_invalid_connection":
		return "number of TCP4 input no-lookup invalid connection packets"
	case "tcp4_input_nolookup_length":
		return "number of TCP4 input no-lookup length error packets"
	case "tcp4_input_nolookup_link_local_rw":
		return "number of TCP4 input no-lookup link local read/write packets"
	case "tcp4_input_nolookup_lookup_drops":
		return "number of TCP4 input no-lookup lookup drops packets"
	case "tcp4_input_nolookup_msg_queue_full":
		return "number of TCP4 input no-lookup packets dropped due to full message queue"
	case "tcp4_input_nolookup_no_listener":
		return "number of TCP4 input no-lookup no listener packets"
	case "tcp4_input_nolookup_none":
		return "number of TCP4 input no-lookup none packets"
	case "tcp4_input_nolookup_options":
		return "number of TCP4 input no-lookup options packets"
	case "tcp4_input_nolookup_partially_enqueued":
		return "number of TCP4 input no-lookup partially enqueued packets"
	case "tcp4_input_nolookup_paws":
		return "number of TCP4 input no-lookup PAWS packets"
	case "tcp4_input_nolookup_pkts_sent":
		return "number of TCP4 input no-lookup packets sent"
	case "tcp4_input_nolookup_punt":
		return "number of TCP4 input no-lookup punt packets"
	case "tcp4_input_nolookup_rcv_wnd":
		return "number of TCP4 input no-lookup receive window packets"
	case "tcp4_input_nolookup_rst_rcvd":
		return "number of TCP4 input no-lookup RST received packets"
	case "tcp4_input_nolookup_rst_sent":
		return "number of TCP4 input no-lookup RST sent packets"
	case "tcp4_input_nolookup_segment_invalid":
		return "number of TCP4 input no-lookup invalid segment packets"
	case "tcp4_input_nolookup_segment_old":
		return "number of TCP4 input no-lookup old segment packets"
	case "tcp4_input_nolookup_spurious_syn":
		return "number of TCP4 input no-lookup spurious SYN packets"
	case "tcp4_input_nolookup_spurious_syn_ack":
		return "number of TCP4 input no-lookup spurious SYN-ACK packets"
	case "tcp4_input_nolookup_syn_acks_rcvd":
		return "number of TCP4 input no-lookup SYN-ACK received packets"
	case "tcp4_input_nolookup_syns_rcvd":
		return "number of TCP4 input no-lookup SYN received packets"
	case "tcp4_input_nolookup_wrong_thread":
		return "number of TCP4 input no-lookup wrong thread packets"
	case "tcp4_input_nolookup_zero_rwnd":
		return "number of TCP4 input no-lookup zero receive window packets"
	case "tcp4_input_none":
		return "number of TCP4 input none packets"
	case "tcp4_input_options":
		return "number of TCP4 input options packets"
	case "tcp4_input_partially_enqueued":
		return "number of TCP4 input partially enqueued packets"
	case "tcp4_input_paws":
		return "number of TCP4 input PAWS packets"
	case "tcp4_input_pkts_sent":
		return "number of TCP4 input packets sent"
	case "tcp4_input_punt":
		return "number of TCP4 input punt packets"
	case "tcp4_input_rcv_wnd":
		return "number of TCP4 input receive window packets"
	case "tcp4_input_rst_rcvd":
		return "number of TCP4 input RST received packets"
	case "tcp4_input_rst_sent":
		return "number of TCP4 input RST sent packets"
	case "tcp4_input_segment_invalid":
		return "number of TCP4 input invalid segment packets"
	case "tcp4_input_segment_old":
		return "number of TCP4 input old segment packets"
	case "tcp4_input_spurious_syn":
		return "number of TCP4 input spurious SYN packets"
	case "tcp4_input_spurious_syn_ack":
		return "number of TCP4 input spurious SYN-ACK packets"
	case "tcp4_input_syn_acks_rcvd":
		return "number of TCP4 input SYN-ACK received packets"
	case "tcp4_input_syns_rcvd":
		return "number of TCP4 input SYN received packets"
	case "tcp4_input_wrong_thread":
		return "number of TCP4 input wrong thread packets"
	case "tcp4_input_zero_rwnd":
		return "number of TCP4 input zero receive window packets"
	case "tcp4_listen_ack_dup":
		return "number of TCP4 listen duplicate ACK packets"
	case "tcp4_listen_ack_future":
		return "number of TCP4 listen future ACK packets"
	case "tcp4_listen_ack_invalid":
		return "number of TCP4 listen invalid ACK packets"
	case "tcp4_listen_ack_ok":
		return "number of TCP4 listen valid ACK packets"
	case "tcp4_listen_ack_old":
		return "number of TCP4 listen old ACK packets"
	case "tcp4_listen_conn_accepted":
		return "number of TCP4 listen connection accepted packets"
	case "tcp4_listen_connection_closed":
		return "number of TCP4 listen connection closed packets"
	case "tcp4_listen_create_exists":
		return "number of TCP4 listen create exists packets"
	case "tcp4_listen_create_session_fail":
		return "number of TCP4 listen create session fail packets"
	case "tcp4_listen_dispatch":
		return "number of TCP4 listen dispatch packets"
	case "tcp4_listen_enqueued":
		return "number of TCP4 listen enqueued packets"
	case "tcp4_listen_enqueued_ooo":
		return "number of TCP4 listen out-of-order enqueued packets"
	case "tcp4_listen_fifo_full":
		return "number of TCP4 listen packets dropped due to full FIFO"
	case "tcp4_listen_filtered":
		return "number of TCP4 listen filtered packets"
	case "tcp4_listen_fin_rcvd":
		return "number of TCP4 listen FIN received packets"
	case "tcp4_listen_invalid_connection":
		return "number of TCP4 listen invalid connection packets"
	case "tcp4_listen_length":
		return "number of TCP4 listen length error packets"
	case "tcp4_listen_link_local_rw":
		return "number of TCP4 listen link local read/write packets"
	case "tcp4_listen_lookup_drops":
		return "number of TCP4 listen lookup drops packets"
	case "tcp4_listen_msg_queue_full":
		return "number of TCP4 listen packets dropped due to full message queue"
	case "tcp4_listen_no_listener":
		return "number of TCP4 listen no listener packets"
	case "tcp4_listen_none":
		return "number of TCP4 listen none packets"
	case "tcp4_listen_options":
		return "number of TCP4 listen options packets"
	case "tcp4_listen_partially_enqueued":
		return "number of TCP4 listen partially enqueued packets"
	case "tcp4_listen_paws":
		return "number of TCP4 listen PAWS packets"
	case "tcp4_listen_pkts_sent":
		return "number of TCP4 listen packets sent"
	case "tcp4_listen_punt":
		return "number of TCP4 listen punt packets"
	case "tcp4_listen_rcv_wnd":
		return "number of TCP4 listen receive window packets"
	case "tcp4_listen_rst_rcvd":
		return "number of TCP4 listen RST received packets"
	case "tcp4_listen_rst_sent":
		return "number of TCP4 listen RST sent packets"
	case "tcp4_listen_segment_invalid":
		return "number of TCP4 listen invalid segment packets"
	case "tcp4_listen_segment_old":
		return "number of TCP4 listen old segment packets"
	case "tcp4_listen_spurious_syn":
		return "number of TCP4 listen spurious SYN packets"
	case "tcp4_listen_spurious_syn_ack":
		return "number of TCP4 listen spurious SYN-ACK packets"
	case "tcp4_listen_syn_acks_rcvd":
		return "number of TCP4 listen SYN-ACK received packets"
	case "tcp4_listen_syns_rcvd":
		return "number of TCP4 listen SYN received packets"
	case "tcp4_listen_wrong_thread":
		return "number of TCP4 listen wrong thread packets"
	case "tcp4_listen_zero_rwnd":
		return "number of TCP4 listen zero receive window packets"
	case "tcp4_output_ack_dup":
		return "number of TCP4 output duplicate ACK packets"
	case "tcp4_output_ack_future":
		return "number of TCP4 output future ACK packets"
	case "tcp4_output_ack_invalid":
		return "number of TCP4 output invalid ACK packets"
	case "tcp4_output_ack_ok":
		return "number of TCP4 output valid ACK packets"
	case "tcp4_output_ack_old":
		return "number of TCP4 output old ACK packets"
	case "tcp4_output_conn_accepted":
		return "number of TCP4 output connection accepted packets"
	case "tcp4_output_connection_closed":
		return "number of TCP4 output connection closed packets"
	case "tcp4_output_create_exists":
		return "number of TCP4 output create exists packets"
	case "tcp4_output_create_session_fail":
		return "number of TCP4 output create session fail packets"
	case "tcp4_output_dispatch":
		return "number of TCP4 output dispatch packets"
	case "tcp4_output_enqueued":
		return "number of TCP4 output enqueued packets"
	case "tcp4_output_enqueued_ooo":
		return "number of TCP4 output out-of-order enqueued packets"
	case "tcp4_output_fifo_full":
		return "number of TCP4 output packets dropped due to full FIFO"
	case "tcp4_output_filtered":
		return "number of TCP4 output filtered packets"
	case "tcp4_output_fin_rcvd":
		return "number of TCP4 output FIN received packets"
	case "tcp4_output_invalid_connection":
		return "number of TCP4 output invalid connection packets"
	case "tcp4_output_length":
		return "number of TCP4 output length error packets"
	case "tcp4_output_link_local_rw":
		return "number of TCP4 output link local read/write packets"
	case "tcp4_output_lookup_drops":
		return "number of TCP4 output lookup drops packets"
	case "tcp4_output_msg_queue_full":
		return "number of TCP4 output packets dropped due to full message queue"
	case "tcp4_output_no_listener":
		return "number of TCP4 output no listener packets"
	case "tcp4_output_none":
		return "number of TCP4 output none packets"
	case "tcp4_output_options":
		return "number of TCP4 output options packets"
	case "tcp4_output_partially_enqueued":
		return "number of TCP4 output partially enqueued packets"
	case "tcp4_output_paws":
		return "number of TCP4 output PAWS packets"
	case "tcp4_output_pkts_sent":
		return "number of TCP4 output packets sent"
	case "tcp4_output_punt":
		return "number of TCP4 output punt packets"
	case "tcp4_output_rcv_wnd":
		return "number of TCP4 output receive window packets"
	case "tcp4_output_rst_rcvd":
		return "number of TCP4 output RST received packets"
	case "tcp4_output_rst_sent":
		return "number of TCP4 output RST sent packets"
	case "tcp4_output_segment_invalid":
		return "number of TCP4 output invalid segment packets"
	case "tcp4_output_segment_old":
		return "number of TCP4 output old segment packets"
	case "tcp4_output_spurious_syn":
		return "number of TCP4 output spurious SYN packets"
	case "tcp4_output_spurious_syn_ack":
		return "number of TCP4 output spurious SYN-ACK packets"
	case "tcp4_output_syn_acks_rcvd":
		return "number of TCP4 output SYN-ACK received packets"
	case "tcp4_output_syns_rcvd":
		return "number of TCP4 output SYN received packets"
	case "tcp4_output_wrong_thread":
		return "number of TCP4 output wrong thread packets"
	case "tcp4_output_zero_rwnd":
		return "number of TCP4 output zero receive window packets"
	case "tcp4_rcv_process_ack_dup":
		return "number of TCP4 receive process duplicate ACK packets"
	case "tcp4_rcv_process_ack_future":
		return "number of TCP4 receive process future ACK packets"
	case "tcp4_rcv_process_ack_invalid":
		return "number of TCP4 receive process invalid ACK packets"
	case "tcp4_rcv_process_ack_ok":
		return "number of TCP4 receive process valid ACK packets"
	case "tcp4_rcv_process_ack_old":
		return "number of TCP4 receive process old ACK packets"
	case "tcp4_rcv_process_conn_accepted":
		return "number of TCP4 receive process connection accepted packets"
	case "tcp4_rcv_process_connection_closed":
		return "number of TCP4 receive process connection closed packets"
	case "tcp4_rcv_process_create_exists":
		return "number of TCP4 receive process create exists packets"
	case "tcp4_rcv_process_create_session_fail":
		return "number of TCP4 receive process create session fail packets"
	case "tcp4_rcv_process_dispatch":
		return "number of TCP4 receive process dispatch packets"
	case "tcp4_rcv_process_enqueued":
		return "number of TCP4 receive process enqueued packets"
	case "tcp4_rcv_process_enqueued_ooo":
		return "number of TCP4 receive process out-of-order enqueued packets"
	case "tcp4_rcv_process_fifo_full":
		return "number of TCP4 receive process packets dropped due to full FIFO"
	case "tcp4_rcv_process_filtered":
		return "number of TCP4 receive process filtered packets"
	case "tcp4_rcv_process_fin_rcvd":
		return "number of TCP4 receive process FIN received packets"
	case "tcp4_rcv_process_invalid_connection":
		return "number of TCP4 receive process invalid connection packets"
	case "tcp4_rcv_process_length":
		return "number of TCP4 receive process length error packets"
	case "tcp4_rcv_process_link_local_rw":
		return "number of TCP4 receive process link local read/write packets"
	case "tcp4_rcv_process_lookup_drops":
		return "number of TCP4 receive process lookup drops packets"
	case "tcp4_rcv_process_msg_queue_full":
		return "number of TCP4 receive process packets dropped due to full message queue"
	case "tcp4_rcv_process_no_listener":
		return "number of TCP4 receive process no listener packets"
	case "tcp4_rcv_process_none":
		return "number of TCP4 receive process none packets"
	case "tcp4_rcv_process_options":
		return "number of TCP4 receive process options packets"
	case "tcp4_rcv_process_partially_enqueued":
		return "number of TCP4 receive process partially enqueued packets"
	case "tcp4_rcv_process_paws":
		return "number of TCP4 receive process PAWS packets"
	case "tcp4_rcv_process_pkts_sent":
		return "number of TCP4 receive process packets sent"
	case "tcp4_rcv_process_punt":
		return "number of TCP4 receive process punt packets"
	case "tcp4_rcv_process_rcv_wnd":
		return "number of TCP4 receive process receive window packets"
	case "tcp4_rcv_process_rst_rcvd":
		return "number of TCP4 receive process RST received packets"
	case "tcp4_rcv_process_rst_sent":
		return "number of TCP4 receive process RST sent packets"
	case "tcp4_rcv_process_segment_invalid":
		return "number of TCP4 receive process invalid segment packets"
	case "tcp4_rcv_process_segment_old":
		return "number of TCP4 receive process old segment packets"
	case "tcp4_rcv_process_spurious_syn":
		return "number of TCP4 receive process spurious SYN packets"
	case "tcp4_rcv_process_spurious_syn_ack":
		return "number of TCP4 receive process spurious SYN-ACK packets"
	case "tcp4_rcv_process_syn_acks_rcvd":
		return "number of TCP4 receive process SYN-ACK received packets"
	case "tcp4_rcv_process_syns_rcvd":
		return "number of TCP4 receive process SYN received packets"
	case "tcp4_rcv_process_wrong_thread":
		return "number of TCP4 receive process wrong thread packets"
	case "tcp4_rcv_process_zero_rwnd":
		return "number of TCP4 receive process zero receive window packets"
	case "tcp4_reset_ack_dup":
		return "number of TCP4 reset duplicate ACK packets"
	case "tcp4_reset_ack_future":
		return "number of TCP4 reset future ACK packets"
	case "tcp4_reset_ack_invalid":
		return "number of TCP4 reset invalid ACK packets"
	case "tcp4_reset_ack_ok":
		return "number of TCP4 reset valid ACK packets"
	case "tcp4_reset_ack_old":
		return "number of TCP4 reset old ACK packets"
	case "tcp4_reset_conn_accepted":
		return "number of TCP4 reset connection accepted packets"
	case "tcp4_reset_connection_closed":
		return "number of TCP4 reset connection closed packets"
	case "tcp4_reset_create_exists":
		return "number of TCP4 reset create exists packets"
	case "tcp4_reset_create_session_fail":
		return "number of TCP4 reset create session fail packets"
	case "tcp4_reset_dispatch":
		return "number of TCP4 reset dispatch packets"
	case "tcp4_reset_enqueued":
		return "number of TCP4 reset enqueued packets"
	case "tcp4_reset_enqueued_ooo":
		return "number of TCP4 reset out-of-order enqueued packets"
	case "tcp4_reset_fifo_full":
		return "number of TCP4 reset packets dropped due to full FIFO"
	case "tcp4_reset_filtered":
		return "number of TCP4 reset filtered packets"
	case "tcp4_reset_fin_rcvd":
		return "number of TCP4 reset FIN received packets"
	case "tcp4_reset_invalid_connection":
		return "number of TCP4 reset invalid connection packets"
	case "tcp4_reset_length":
		return "number of TCP4 reset length error packets"
	case "tcp4_reset_link_local_rw":
		return "number of TCP4 reset link local read/write packets"
	case "tcp4_reset_lookup_drops":
		return "number of TCP4 reset lookup drops packets"
	case "tcp4_reset_msg_queue_full":
		return "number of TCP4 reset packets dropped due to full message queue"
	case "tcp4_reset_no_listener":
		return "number of TCP4 reset no listener packets"
	case "tcp4_reset_none":
		return "number of TCP4 reset none packets"
	case "tcp4_reset_options":
		return "number of TCP4 reset options packets"
	case "tcp4_reset_partially_enqueued":
		return "number of TCP4 reset partially enqueued packets"
	case "tcp4_reset_paws":
		return "number of TCP4 reset PAWS packets"
	case "tcp4_reset_pkts_sent":
		return "number of TCP4 reset packets sent"
	case "tcp4_reset_punt":
		return "number of TCP4 reset punt packets"
	case "tcp4_reset_rcv_wnd":
		return "number of TCP4 reset receive window packets"
	case "tcp4_reset_rst_rcvd":
		return "number of TCP4 reset RST received packets"
	case "tcp4_reset_rst_sent":
		return "number of TCP4 reset RST sent packets"
	case "tcp4_reset_segment_invalid":
		return "number of TCP4 reset invalid segment packets"
	case "tcp4_reset_segment_old":
		return "number of TCP4 reset old segment packets"
	case "tcp4_reset_spurious_syn":
		return "number of TCP4 reset spurious SYN packets"
	case "tcp4_reset_spurious_syn_ack":
		return "number of TCP4 reset spurious SYN-ACK packets"
	case "tcp4_reset_syn_acks_rcvd":
		return "number of TCP4 reset SYN-ACK received packets"
	case "tcp4_reset_syns_rcvd":
		return "number of TCP4 reset SYN received packets"
	case "tcp4_reset_wrong_thread":
		return "number of TCP4 reset wrong thread packets"
	case "tcp4_reset_zero_rwnd":
		return "number of TCP4 reset zero receive window packets"
	case "tcp4_syn_sent_ack_dup":
		return "number of TCP4 SYN sent duplicate ACK packets"
	case "tcp4_syn_sent_ack_future":
		return "number of TCP4 SYN sent future ACK packets"
	case "tcp4_syn_sent_ack_invalid":
		return "number of TCP4 SYN sent invalid ACK packets"
	case "tcp4_syn_sent_ack_ok":
		return "number of TCP4 SYN sent valid ACK packets"
	case "tcp4_syn_sent_ack_old":
		return "number of TCP4 SYN sent old ACK packets"
	case "tcp4_syn_sent_conn_accepted":
		return "number of TCP4 SYN sent connection accepted packets"
	case "tcp4_syn_sent_connection_closed":
		return "number of TCP4 SYN sent connection closed packets"
	case "tcp4_syn_sent_create_exists":
		return "number of TCP4 SYN sent create exists packets"
	case "tcp4_syn_sent_create_session_fail":
		return "number of TCP4 SYN sent create session fail packets"
	case "tcp4_syn_sent_dispatch":
		return "number of TCP4 SYN sent dispatch packets"
	case "tcp4_syn_sent_enqueued":
		return "number of TCP4 SYN sent enqueued packets"
	case "tcp4_syn_sent_enqueued_ooo":
		return "number of TCP4 SYN sent out-of-order enqueued packets"
	case "tcp4_syn_sent_fifo_full":
		return "number of TCP4 SYN sent packets dropped due to full FIFO"
	case "tcp4_syn_sent_filtered":
		return "number of TCP4 SYN sent filtered packets"
	case "tcp4_syn_sent_fin_rcvd":
		return "number of TCP4 SYN sent FIN received packets"
	case "tcp4_syn_sent_invalid_connection":
		return "number of TCP4 SYN sent invalid connection packets"
	case "tcp4_syn_sent_length":
		return "number of TCP4 SYN sent length error packets"
	case "tcp4_syn_sent_link_local_rw":
		return "number of TCP4 SYN sent link local read/write packets"
	case "tcp4_syn_sent_lookup_drops":
		return "number of TCP4 SYN sent lookup drops packets"
	case "tcp4_syn_sent_msg_queue_full":
		return "number of TCP4 SYN sent packets dropped due to full message queue"
	case "tcp4_syn_sent_no_listener":
		return "number of TCP4 SYN sent no listener packets"
	case "tcp4_syn_sent_none":
		return "number of TCP4 SYN sent none packets"
	case "tcp4_syn_sent_options":
		return "number of TCP4 SYN sent options packets"
	case "tcp4_syn_sent_partially_enqueued":
		return "number of TCP4 SYN sent partially enqueued packets"
	case "tcp4_syn_sent_paws":
		return "number of TCP4 SYN sent PAWS packets"
	case "tcp4_syn_sent_pkts_sent":
		return "number of TCP4 SYN sent packets sent"
	case "tcp4_syn_sent_punt":
		return "number of TCP4 SYN sent punt packets"
	case "tcp4_syn_sent_rcv_wnd":
		return "number of TCP4 SYN sent receive window packets"
	case "tcp4_syn_sent_rst_rcvd":
		return "number of TCP4 SYN sent RST received packets"
	case "tcp4_syn_sent_rst_sent":
		return "number of TCP4 SYN sent RST sent packets"
	case "tcp4_syn_sent_segment_invalid":
		return "number of TCP4 SYN sent invalid segment packets"
	case "tcp4_syn_sent_segment_old":
		return "number of TCP4 SYN sent old segment packets"
	case "tcp4_syn_sent_spurious_syn":
		return "number of TCP4 SYN sent spurious SYN packets"
	case "tcp4_syn_sent_spurious_syn_ack":
		return "number of TCP4 SYN sent spurious SYN-ACK packets"
	case "tcp4_syn_sent_syn_acks_rcvd":
		return "number of TCP4 SYN sent SYN-ACK received packets"
	case "tcp4_syn_sent_syns_rcvd":
		return "number of TCP4 SYN sent SYN received packets"
	case "tcp4_syn_sent_wrong_thread":
		return "number of TCP4 SYN sent wrong thread packets"
	case "tcp4_syn_sent_zero_rwnd":
		return "number of TCP4 SYN sent zero receive window packets"
	// /err/tcp6/... stats
	case "tcp6_drop_ack_dup":
		return "number of TCP6 dropped duplicate ACK packets"
	case "tcp6_drop_ack_future":
		return "number of TCP6 dropped future ACK packets"
	case "tcp6_drop_ack_invalid":
		return "number of TCP6 dropped invalid ACK packets"
	case "tcp6_drop_ack_ok":
		return "number of TCP6 dropped valid ACK packets"
	case "tcp6_drop_ack_old":
		return "number of TCP6 dropped old ACK packets"
	case "tcp6_drop_conn_accepted":
		return "number of TCP6 dropped connection accepted packets"
	case "tcp6_drop_connection_closed":
		return "number of TCP6 dropped connection closed packets"
	case "tcp6_drop_create_exists":
		return "number of TCP6 dropped create exists packets"
	case "tcp6_drop_create_session_fail":
		return "number of TCP6 dropped create session fail packets"
	case "tcp6_drop_dispatch":
		return "number of TCP6 dropped dispatch packets"
	case "tcp6_drop_enqueued":
		return "number of TCP6 dropped enqueued packets"
	case "tcp6_drop_enqueued_ooo":
		return "number of TCP6 dropped out-of-order enqueued packets"
	case "tcp6_drop_fifo_full":
		return "number of TCP6 dropped packets due to full FIFO"
	case "tcp6_drop_filtered":
		return "number of TCP6 dropped filtered packets"
	case "tcp6_drop_fin_rcvd":
		return "number of TCP6 dropped FIN received packets"
	case "tcp6_drop_invalid_connection":
		return "number of TCP6 dropped invalid connection packets"
	case "tcp6_drop_length":
		return "number of TCP6 dropped length error packets"
	case "tcp6_drop_link_local_rw":
		return "number of TCP6 dropped link local read/write packets"
	case "tcp6_drop_lookup_drops":
		return "number of TCP6 dropped lookup drops packets"
	case "tcp6_drop_msg_queue_full":
		return "number of TCP6 dropped packets due to full message queue"
	case "tcp6_drop_no_listener":
		return "number of TCP6 dropped no listener packets"
	case "tcp6_drop_none":
		return "number of TCP6 dropped none packets"
	case "tcp6_drop_options":
		return "number of TCP6 dropped options packets"
	case "tcp6_drop_partially_enqueued":
		return "number of TCP6 dropped partially enqueued packets"
	case "tcp6_drop_paws":
		return "number of TCP6 dropped PAWS packets"
	case "tcp6_drop_pkts_sent":
		return "number of TCP6 dropped packets sent"
	case "tcp6_drop_punt":
		return "number of TCP6 dropped punt packets"
	case "tcp6_drop_rcv_wnd":
		return "number of TCP6 dropped receive window packets"
	case "tcp6_drop_rst_rcvd":
		return "number of TCP6 dropped RST received packets"
	case "tcp6_drop_rst_sent":
		return "number of TCP6 dropped RST sent packets"
	case "tcp6_drop_segment_invalid":
		return "number of TCP6 dropped invalid segment packets"
	case "tcp6_drop_segment_old":
		return "number of TCP6 dropped old segment packets"
	case "tcp6_drop_spurious_syn":
		return "number of TCP6 dropped spurious SYN packets"
	case "tcp6_drop_spurious_syn_ack":
		return "number of TCP6 dropped spurious SYN-ACK packets"
	case "tcp6_drop_syn_acks_rcvd":
		return "number of TCP6 dropped SYN-ACK received packets"
	case "tcp6_drop_syns_rcvd":
		return "number of TCP6 dropped SYN received packets"
	case "tcp6_drop_wrong_thread":
		return "number of TCP6 dropped wrong thread packets"
	case "tcp6_drop_zero_rwnd":
		return "number of TCP6 dropped zero receive window packets"
	case "tcp6_established_ack_dup":
		return "number of TCP6 established duplicate ACK packets"
	case "tcp6_established_ack_future":
		return "number of TCP6 established future ACK packets"
	case "tcp6_established_ack_invalid":
		return "number of TCP6 established invalid ACK packets"
	case "tcp6_established_ack_ok":
		return "number of TCP6 established valid ACK packets"
	case "tcp6_established_ack_old":
		return "number of TCP6 established old ACK packets"
	case "tcp6_established_conn_accepted":
		return "number of TCP6 established connection accepted packets"
	case "tcp6_established_connection_closed":
		return "number of TCP6 established connection closed packets"
	case "tcp6_established_create_exists":
		return "number of TCP6 established create exists packets"
	case "tcp6_established_create_session_fail":
		return "number of TCP6 established create session fail packets"
	case "tcp6_established_dispatch":
		return "number of TCP6 established dispatch packets"
	case "tcp6_established_enqueued":
		return "number of TCP6 established enqueued packets"
	case "tcp6_established_enqueued_ooo":
		return "number of TCP6 established out-of-order enqueued packets"
	case "tcp6_established_fifo_full":
		return "number of TCP6 established packets dropped due to full FIFO"
	case "tcp6_established_filtered":
		return "number of TCP6 established filtered packets"
	case "tcp6_established_fin_rcvd":
		return "number of TCP6 established FIN received packets"
	case "tcp6_established_invalid_connection":
		return "number of TCP6 established invalid connection packets"
	case "tcp6_established_length":
		return "number of TCP6 established length error packets"
	case "tcp6_established_link_local_rw":
		return "number of TCP6 established link local read/write packets"
	case "tcp6_established_lookup_drops":
		return "number of TCP6 established lookup drops packets"
	case "tcp6_established_msg_queue_full":
		return "number of TCP6 established packets dropped due to full message queue"
	case "tcp6_established_no_listener":
		return "number of TCP6 established no listener packets"
	case "tcp6_established_none":
		return "number of TCP6 established none packets"
	case "tcp6_established_options":
		return "number of TCP6 established options packets"
	case "tcp6_established_partially_enqueued":
		return "number of TCP6 established partially enqueued packets"
	case "tcp6_established_paws":
		return "number of TCP6 established PAWS packets"
	case "tcp6_established_pkts_sent":
		return "number of TCP6 established packets sent"
	case "tcp6_established_punt":
		return "number of TCP6 established punt packets"
	case "tcp6_established_rcv_wnd":
		return "number of TCP6 established receive window packets"
	case "tcp6_established_rst_rcvd":
		return "number of TCP6 established RST received packets"
	case "tcp6_established_rst_sent":
		return "number of TCP6 established RST sent packets"
	case "tcp6_established_segment_invalid":
		return "number of TCP6 established invalid segment packets"
	case "tcp6_established_segment_old":
		return "number of TCP6 established old segment packets"
	case "tcp6_established_spurious_syn":
		return "number of TCP6 established spurious SYN packets"
	case "tcp6_established_spurious_syn_ack":
		return "number of TCP6 established spurious SYN-ACK packets"
	case "tcp6_established_syn_acks_rcvd":
		return "number of TCP6 established SYN-ACK received packets"
	case "tcp6_established_syns_rcvd":
		return "number of TCP6 established SYN received packets"
	case "tcp6_established_wrong_thread":
		return "number of TCP6 established wrong thread packets"
	case "tcp6_established_zero_rwnd":
		return "number of TCP6 established zero receive window packets"
	case "tcp6_input_ack_dup":
		return "number of TCP6 input duplicate ACK packets"
	case "tcp6_input_ack_future":
		return "number of TCP6 input future ACK packets"
	case "tcp6_input_ack_invalid":
		return "number of TCP6 input invalid ACK packets"
	case "tcp6_input_ack_ok":
		return "number of TCP6 input valid ACK packets"
	case "tcp6_input_ack_old":
		return "number of TCP6 input old ACK packets"
	case "tcp6_input_conn_accepted":
		return "number of TCP6 input connection accepted packets"
	case "tcp6_input_connection_closed":
		return "number of TCP6 input connection closed packets"
	case "tcp6_input_create_exists":
		return "number of TCP6 input create exists packets"
	case "tcp6_input_create_session_fail":
		return "number of TCP6 input create session fail packets"
	case "tcp6_input_dispatch":
		return "number of TCP6 input dispatch packets"
	case "tcp6_input_enqueued":
		return "number of TCP6 input enqueued packets"
	case "tcp6_input_enqueued_ooo":
		return "number of TCP6 input out-of-order enqueued packets"
	case "tcp6_input_fifo_full":
		return "number of TCP6 input packets dropped due to full FIFO"
	case "tcp6_input_filtered":
		return "number of TCP6 input filtered packets"
	case "tcp6_input_fin_rcvd":
		return "number of TCP6 input FIN received packets"
	case "tcp6_input_invalid_connection":
		return "number of TCP6 input invalid connection packets"
	case "tcp6_input_length":
		return "number of TCP6 input length error packets"
	case "tcp6_input_link_local_rw":
		return "number of TCP6 input link local read/write packets"
	case "tcp6_input_lookup_drops":
		return "number of TCP6 input lookup drops packets"
	case "tcp6_input_msg_queue_full":
		return "number of TCP6 input packets dropped due to full message queue"
	case "tcp6_input_no_listener":
		return "number of TCP6 input no listener packets"
	case "tcp6_input_nolookup_ack_dup":
		return "number of TCP6 input no-lookup duplicate ACK packets"
	case "tcp6_input_nolookup_ack_future":
		return "number of TCP6 input no-lookup future ACK packets"
	case "tcp6_input_nolookup_ack_invalid":
		return "number of TCP6 input no-lookup invalid ACK packets"
	case "tcp6_input_nolookup_ack_ok":
		return "number of TCP6 input no-lookup valid ACK packets"
	case "tcp6_input_nolookup_ack_old":
		return "number of TCP6 input no-lookup old ACK packets"
	case "tcp6_input_nolookup_conn_accepted":
		return "number of TCP6 input no-lookup connection accepted packets"
	case "tcp6_input_nolookup_connection_closed":
		return "number of TCP6 input no-lookup connection closed packets"
	case "tcp6_input_nolookup_create_exists":
		return "number of TCP6 input no-lookup create exists packets"
	case "tcp6_input_nolookup_create_session_fail":
		return "number of TCP6 input no-lookup create session fail packets"
	case "tcp6_input_nolookup_dispatch":
		return "number of TCP6 input no-lookup dispatch packets"
	case "tcp6_input_nolookup_enqueued":
		return "number of TCP6 input no-lookup enqueued packets"
	case "tcp6_input_nolookup_enqueued_ooo":
		return "number of TCP6 input no-lookup out-of-order enqueued packets"
	case "tcp6_input_nolookup_fifo_full":
		return "number of TCP6 input no-lookup packets dropped due to full FIFO"
	case "tcp6_input_nolookup_filtered":
		return "number of TCP6 input no-lookup filtered packets"
	case "tcp6_input_nolookup_fin_rcvd":
		return "number of TCP6 input no-lookup FIN received packets"
	case "tcp6_input_nolookup_invalid_connection":
		return "number of TCP6 input no-lookup invalid connection packets"
	case "tcp6_input_nolookup_length":
		return "number of TCP6 input no-lookup length error packets"
	case "tcp6_input_nolookup_link_local_rw":
		return "number of TCP6 input no-lookup link local read/write packets"
	case "tcp6_input_nolookup_lookup_drops":
		return "number of TCP6 input no-lookup lookup drops packets"
	case "tcp6_input_nolookup_msg_queue_full":
		return "number of TCP6 input no-lookup packets dropped due to full message queue"
	case "tcp6_input_nolookup_no_listener":
		return "number of TCP6 input no-lookup no listener packets"
	case "tcp6_input_nolookup_none":
		return "number of TCP6 input no-lookup none packets"
	case "tcp6_input_nolookup_options":
		return "number of TCP6 input no-lookup options packets"
	case "tcp6_input_nolookup_partially_enqueued":
		return "number of TCP6 input no-lookup partially enqueued packets"
	case "tcp6_input_nolookup_paws":
		return "number of TCP6 input no-lookup PAWS packets"
	case "tcp6_input_nolookup_pkts_sent":
		return "number of TCP6 input no-lookup packets sent"
	case "tcp6_input_nolookup_punt":
		return "number of TCP6 input no-lookup punt packets"
	case "tcp6_input_nolookup_rcv_wnd":
		return "number of TCP6 input no-lookup receive window packets"
	case "tcp6_input_nolookup_rst_rcvd":
		return "number of TCP6 input no-lookup RST received packets"
	case "tcp6_input_nolookup_rst_sent":
		return "number of TCP6 input no-lookup RST sent packets"
	case "tcp6_input_nolookup_segment_invalid":
		return "number of TCP6 input no-lookup invalid segment packets"
	case "tcp6_input_nolookup_segment_old":
		return "number of TCP6 input no-lookup old segment packets"
	case "tcp6_input_nolookup_spurious_syn":
		return "number of TCP6 input no-lookup spurious SYN packets"
	case "tcp6_input_nolookup_spurious_syn_ack":
		return "number of TCP6 input no-lookup spurious SYN-ACK packets"
	case "tcp6_input_nolookup_syn_acks_rcvd":
		return "number of TCP6 input no-lookup SYN-ACK received packets"
	case "tcp6_input_nolookup_syns_rcvd":
		return "number of TCP6 input no-lookup SYN received packets"
	case "tcp6_input_nolookup_wrong_thread":
		return "number of TCP6 input no-lookup wrong thread packets"
	case "tcp6_input_nolookup_zero_rwnd":
		return "number of TCP6 input no-lookup zero receive window packets"
	case "tcp6_input_none":
		return "number of TCP6 input none packets"
	case "tcp6_input_options":
		return "number of TCP6 input options packets"
	case "tcp6_input_partially_enqueued":
		return "number of TCP6 input partially enqueued packets"
	case "tcp6_input_paws":
		return "number of TCP6 input PAWS packets"
	case "tcp6_input_pkts_sent":
		return "number of TCP6 input packets sent"
	case "tcp6_input_punt":
		return "number of TCP6 input punt packets"
	case "tcp6_input_rcv_wnd":
		return "number of TCP6 input receive window packets"
	case "tcp6_input_rst_rcvd":
		return "number of TCP6 input RST received packets"
	case "tcp6_input_rst_sent":
		return "number of TCP6 input RST sent packets"
	case "tcp6_input_segment_invalid":
		return "number of TCP6 input invalid segment packets"
	case "tcp6_input_segment_old":
		return "number of TCP6 input old segment packets"
	case "tcp6_input_spurious_syn":
		return "number of TCP6 input spurious SYN packets"
	case "tcp6_input_spurious_syn_ack":
		return "number of TCP6 input spurious SYN-ACK packets"
	case "tcp6_input_syn_acks_rcvd":
		return "number of TCP6 input SYN-ACK received packets"
	case "tcp6_input_syns_rcvd":
		return "number of TCP6 input SYN received packets"
	case "tcp6_input_wrong_thread":
		return "number of TCP6 input wrong thread packets"
	case "tcp6_input_zero_rwnd":
		return "number of TCP6 input zero receive window packets"
	case "tcp6_listen_ack_dup":
		return "number of TCP6 listen duplicate ACK packets"
	case "tcp6_listen_ack_future":
		return "number of TCP6 listen future ACK packets"
	case "tcp6_listen_ack_invalid":
		return "number of TCP6 listen invalid ACK packets"
	case "tcp6_listen_ack_ok":
		return "number of TCP6 listen valid ACK packets"
	case "tcp6_listen_ack_old":
		return "number of TCP6 listen old ACK packets"
	case "tcp6_listen_conn_accepted":
		return "number of TCP6 listen connection accepted packets"
	case "tcp6_listen_connection_closed":
		return "number of TCP6 listen connection closed packets"
	case "tcp6_listen_create_exists":
		return "number of TCP6 listen create exists packets"
	case "tcp6_listen_create_session_fail":
		return "number of TCP6 listen create session fail packets"
	case "tcp6_listen_dispatch":
		return "number of TCP6 listen dispatch packets"
	case "tcp6_listen_enqueued":
		return "number of TCP6 listen enqueued packets"
	case "tcp6_listen_enqueued_ooo":
		return "number of TCP6 listen out-of-order enqueued packets"
	case "tcp6_listen_fifo_full":
		return "number of TCP6 listen packets dropped due to full FIFO"
	case "tcp6_listen_filtered":
		return "number of TCP6 listen filtered packets"
	case "tcp6_listen_fin_rcvd":
		return "number of TCP6 listen FIN received packets"
	case "tcp6_listen_invalid_connection":
		return "number of TCP6 listen invalid connection packets"
	case "tcp6_listen_length":
		return "number of TCP6 listen length error packets"
	case "tcp6_listen_link_local_rw":
		return "number of TCP6 listen link local read/write packets"
	case "tcp6_listen_lookup_drops":
		return "number of TCP6 listen lookup drops packets"
	case "tcp6_listen_msg_queue_full":
		return "number of TCP6 listen packets dropped due to full message queue"
	case "tcp6_listen_no_listener":
		return "number of TCP6 listen no listener packets"
	case "tcp6_listen_none":
		return "number of TCP6 listen none packets"
	case "tcp6_listen_options":
		return "number of TCP6 listen options packets"
	case "tcp6_listen_partially_enqueued":
		return "number of TCP6 listen partially enqueued packets"
	case "tcp6_listen_paws":
		return "number of TCP6 listen PAWS packets"
	case "tcp6_listen_pkts_sent":
		return "number of TCP6 listen packets sent"
	case "tcp6_listen_punt":
		return "number of TCP6 listen punt packets"
	case "tcp6_listen_rcv_wnd":
		return "number of TCP6 listen receive window packets"
	case "tcp6_listen_rst_rcvd":
		return "number of TCP6 listen RST received packets"
	case "tcp6_listen_rst_sent":
		return "number of TCP6 listen RST sent packets"
	case "tcp6_listen_segment_invalid":
		return "number of TCP6 listen invalid segment packets"
	case "tcp6_listen_segment_old":
		return "number of TCP6 listen old segment packets"
	case "tcp6_listen_spurious_syn":
		return "number of TCP6 listen spurious SYN packets"
	case "tcp6_listen_spurious_syn_ack":
		return "number of TCP6 listen spurious SYN-ACK packets"
	case "tcp6_listen_syn_acks_rcvd":
		return "number of TCP6 listen SYN-ACK received packets"
	case "tcp6_listen_syns_rcvd":
		return "number of TCP6 listen SYN received packets"
	case "tcp6_listen_wrong_thread":
		return "number of TCP6 listen wrong thread packets"
	case "tcp6_listen_zero_rwnd":
		return "number of TCP6 listen zero receive window packets"
	case "tcp6_output_ack_dup":
		return "number of TCP6 output duplicate ACK packets"
	case "tcp6_output_ack_future":
		return "number of TCP6 output future ACK packets"
	case "tcp6_output_ack_invalid":
		return "number of TCP6 output invalid ACK packets"
	case "tcp6_output_ack_ok":
		return "number of TCP6 output valid ACK packets"
	case "tcp6_output_ack_old":
		return "number of TCP6 output old ACK packets"
	case "tcp6_output_conn_accepted":
		return "number of TCP6 output connection accepted packets"
	case "tcp6_output_connection_closed":
		return "number of TCP6 output connection closed packets"
	case "tcp6_output_create_exists":
		return "number of TCP6 output create exists packets"
	case "tcp6_output_create_session_fail":
		return "number of TCP6 output create session fail packets"
	case "tcp6_output_dispatch":
		return "number of TCP6 output dispatch packets"
	case "tcp6_output_enqueued":
		return "number of TCP6 output enqueued packets"
	case "tcp6_output_enqueued_ooo":
		return "number of TCP6 output out-of-order enqueued packets"
	case "tcp6_output_fifo_full":
		return "number of TCP6 output packets dropped due to full FIFO"
	case "tcp6_output_filtered":
		return "number of TCP6 output filtered packets"
	case "tcp6_output_fin_rcvd":
		return "number of TCP6 output FIN received packets"
	case "tcp6_output_invalid_connection":
		return "number of TCP6 output invalid connection packets"
	case "tcp6_output_length":
		return "number of TCP6 output length error packets"
	case "tcp6_output_link_local_rw":
		return "number of TCP6 output link local read/write packets"
	case "tcp6_output_lookup_drops":
		return "number of TCP6 output lookup drops packets"
	case "tcp6_output_msg_queue_full":
		return "number of TCP6 output packets dropped due to full message queue"
	case "tcp6_output_no_listener":
		return "number of TCP6 output no listener packets"
	case "tcp6_output_none":
		return "number of TCP6 output none packets"
	case "tcp6_output_options":
		return "number of TCP6 output options packets"
	case "tcp6_output_partially_enqueued":
		return "number of TCP6 output partially enqueued packets"
	case "tcp6_output_paws":
		return "number of TCP6 output PAWS packets"
	case "tcp6_output_pkts_sent":
		return "number of TCP6 output packets sent"
	case "tcp6_output_punt":
		return "number of TCP6 output punt packets"
	case "tcp6_output_rcv_wnd":
		return "number of TCP6 output receive window packets"
	case "tcp6_output_rst_rcvd":
		return "number of TCP6 output RST received packets"
	case "tcp6_output_rst_sent":
		return "number of TCP6 output RST sent packets"
	case "tcp6_output_segment_invalid":
		return "number of TCP6 output invalid segment packets"
	case "tcp6_output_segment_old":
		return "number of TCP6 output old segment packets"
	case "tcp6_output_spurious_syn":
		return "number of TCP6 output spurious SYN packets"
	case "tcp6_output_spurious_syn_ack":
		return "number of TCP6 output spurious SYN-ACK packets"
	case "tcp6_output_syn_acks_rcvd":
		return "number of TCP6 output SYN-ACK received packets"
	case "tcp6_output_syns_rcvd":
		return "number of TCP6 output SYN received packets"
	case "tcp6_output_wrong_thread":
		return "number of TCP6 output wrong thread packets"
	case "tcp6_output_zero_rwnd":
		return "number of TCP6 output zero receive window packets"
	case "tcp6_rcv_process_ack_dup":
		return "number of TCP6 receive process duplicate ACK packets"
	case "tcp6_rcv_process_ack_future":
		return "number of TCP6 receive process future ACK packets"
	case "tcp6_rcv_process_ack_invalid":
		return "number of TCP6 receive process invalid ACK packets"
	case "tcp6_rcv_process_ack_ok":
		return "number of TCP6 receive process valid ACK packets"
	case "tcp6_rcv_process_ack_old":
		return "number of TCP6 receive process old ACK packets"
	case "tcp6_rcv_process_conn_accepted":
		return "number of TCP6 receive process connection accepted packets"
	case "tcp6_rcv_process_connection_closed":
		return "number of TCP6 receive process connection closed packets"
	case "tcp6_rcv_process_create_exists":
		return "number of TCP6 receive process create exists packets"
	case "tcp6_rcv_process_create_session_fail":
		return "number of TCP6 receive process create session fail packets"
	case "tcp6_rcv_process_dispatch":
		return "number of TCP6 receive process dispatch packets"
	case "tcp6_rcv_process_enqueued":
		return "number of TCP6 receive process enqueued packets"
	case "tcp6_rcv_process_enqueued_ooo":
		return "number of TCP6 receive process out-of-order enqueued packets"
	case "tcp6_rcv_process_fifo_full":
		return "number of TCP6 receive process packets dropped due to full FIFO"
	case "tcp6_rcv_process_filtered":
		return "number of TCP6 receive process filtered packets"
	case "tcp6_rcv_process_fin_rcvd":
		return "number of TCP6 receive process FIN received packets"
	case "tcp6_rcv_process_invalid_connection":
		return "number of TCP6 receive process invalid connection packets"
	case "tcp6_rcv_process_length":
		return "number of TCP6 receive process length error packets"
	case "tcp6_rcv_process_link_local_rw":
		return "number of TCP6 receive process link local read/write packets"
	case "tcp6_rcv_process_lookup_drops":
		return "number of TCP6 receive process lookup drops packets"
	case "tcp6_rcv_process_msg_queue_full":
		return "number of TCP6 receive process packets dropped due to full message queue"
	case "tcp6_rcv_process_no_listener":
		return "number of TCP6 receive process no listener packets"
	case "tcp6_rcv_process_none":
		return "number of TCP6 receive process none packets"
	case "tcp6_rcv_process_options":
		return "number of TCP6 receive process options packets"
	case "tcp6_rcv_process_partially_enqueued":
		return "number of TCP6 receive process partially enqueued packets"
	case "tcp6_rcv_process_paws":
		return "number of TCP6 receive process PAWS packets"
	case "tcp6_rcv_process_pkts_sent":
		return "number of TCP6 receive process packets sent"
	case "tcp6_rcv_process_punt":
		return "number of TCP6 receive process punt packets"
	case "tcp6_rcv_process_rcv_wnd":
		return "number of TCP6 receive process receive window packets"
	case "tcp6_rcv_process_rst_rcvd":
		return "number of TCP6 receive process RST received packets"
	case "tcp6_rcv_process_rst_sent":
		return "number of TCP6 receive process RST sent packets"
	case "tcp6_rcv_process_segment_invalid":
		return "number of TCP6 receive process invalid segment packets"
	case "tcp6_rcv_process_segment_old":
		return "number of TCP6 receive process old segment packets"
	case "tcp6_rcv_process_spurious_syn":
		return "number of TCP6 receive process spurious SYN packets"
	case "tcp6_rcv_process_spurious_syn_ack":
		return "number of TCP6 receive process spurious SYN-ACK packets"
	case "tcp6_rcv_process_syn_acks_rcvd":
		return "number of TCP6 receive process SYN-ACK received packets"
	case "tcp6_rcv_process_syns_rcvd":
		return "number of TCP6 receive process SYN received packets"
	case "tcp6_rcv_process_wrong_thread":
		return "number of TCP6 receive process wrong thread packets"
	case "tcp6_rcv_process_zero_rwnd":
		return "number of TCP6 receive process zero receive window packets"
	case "tcp6_reset_ack_dup":
		return "number of TCP6 reset duplicate ACK packets"
	case "tcp6_reset_ack_future":
		return "number of TCP6 reset future ACK packets"
	case "tcp6_reset_ack_invalid":
		return "number of TCP6 reset invalid ACK packets"
	case "tcp6_reset_ack_ok":
		return "number of TCP6 reset valid ACK packets"
	case "tcp6_reset_ack_old":
		return "number of TCP6 reset old ACK packets"
	case "tcp6_reset_conn_accepted":
		return "number of TCP6 reset connection accepted packets"
	case "tcp6_reset_connection_closed":
		return "number of TCP6 reset connection closed packets"
	case "tcp6_reset_create_exists":
		return "number of TCP6 reset create exists packets"
	case "tcp6_reset_create_session_fail":
		return "number of TCP6 reset create session fail packets"
	case "tcp6_reset_dispatch":
		return "number of TCP6 reset dispatch packets"
	case "tcp6_reset_enqueued":
		return "number of TCP6 reset enqueued packets"
	case "tcp6_reset_enqueued_ooo":
		return "number of TCP6 reset out-of-order enqueued packets"
	case "tcp6_reset_fifo_full":
		return "number of TCP6 reset packets dropped due to full FIFO"
	case "tcp6_reset_filtered":
		return "number of TCP6 reset filtered packets"
	case "tcp6_reset_fin_rcvd":
		return "number of TCP6 reset FIN received packets"
	case "tcp6_reset_invalid_connection":
		return "number of TCP6 reset invalid connection packets"
	case "tcp6_reset_length":
		return "number of TCP6 reset length error packets"
	case "tcp6_reset_link_local_rw":
		return "number of TCP6 reset link local read/write packets"
	case "tcp6_reset_lookup_drops":
		return "number of TCP6 reset lookup drops packets"
	case "tcp6_reset_msg_queue_full":
		return "number of TCP6 reset packets dropped due to full message queue"
	case "tcp6_reset_no_listener":
		return "number of TCP6 reset no listener packets"
	case "tcp6_reset_none":
		return "number of TCP6 reset none packets"
	case "tcp6_reset_options":
		return "number of TCP6 reset options packets"
	case "tcp6_reset_partially_enqueued":
		return "number of TCP6 reset partially enqueued packets"
	case "tcp6_reset_paws":
		return "number of TCP6 reset PAWS packets"
	case "tcp6_reset_pkts_sent":
		return "number of TCP6 reset packets sent"
	case "tcp6_reset_punt":
		return "number of TCP6 reset punt packets"
	case "tcp6_reset_rcv_wnd":
		return "number of TCP6 reset receive window packets"
	case "tcp6_reset_rst_rcvd":
		return "number of TCP6 reset RST received packets"
	case "tcp6_reset_rst_sent":
		return "number of TCP6 reset RST sent packets"
	case "tcp6_reset_segment_invalid":
		return "number of TCP6 reset invalid segment packets"
	case "tcp6_reset_segment_old":
		return "number of TCP6 reset old segment packets"
	case "tcp6_reset_spurious_syn":
		return "number of TCP6 reset spurious SYN packets"
	case "tcp6_reset_spurious_syn_ack":
		return "number of TCP6 reset spurious SYN-ACK packets"
	case "tcp6_reset_syn_acks_rcvd":
		return "number of TCP6 reset SYN-ACK received packets"
	case "tcp6_reset_syns_rcvd":
		return "number of TCP6 reset SYN received packets"
	case "tcp6_reset_wrong_thread":
		return "number of TCP6 reset wrong thread packets"
	case "tcp6_reset_zero_rwnd":
		return "number of TCP6 reset zero receive window packets"
	case "tcp6_syn_sent_ack_dup":
		return "number of TCP6 SYN sent duplicate ACK packets"
	case "tcp6_syn_sent_ack_future":
		return "number of TCP6 SYN sent future ACK packets"
	case "tcp6_syn_sent_ack_invalid":
		return "number of TCP6 SYN sent invalid ACK packets"
	case "tcp6_syn_sent_ack_ok":
		return "number of TCP6 SYN sent valid ACK packets"
	case "tcp6_syn_sent_ack_old":
		return "number of TCP6 SYN sent old ACK packets"
	case "tcp6_syn_sent_conn_accepted":
		return "number of TCP6 SYN sent connection accepted packets"
	case "tcp6_syn_sent_connection_closed":
		return "number of TCP6 SYN sent connection closed packets"
	case "tcp6_syn_sent_create_exists":
		return "number of TCP6 SYN sent create exists packets"
	case "tcp6_syn_sent_create_session_fail":
		return "number of TCP6 SYN sent create session fail packets"
	case "tcp6_syn_sent_dispatch":
		return "number of TCP6 SYN sent dispatch packets"
	case "tcp6_syn_sent_enqueued":
		return "number of TCP6 SYN sent enqueued packets"
	case "tcp6_syn_sent_enqueued_ooo":
		return "number of TCP6 SYN sent out-of-order enqueued packets"
	case "tcp6_syn_sent_fifo_full":
		return "number of TCP6 SYN sent packets dropped due to full FIFO"
	case "tcp6_syn_sent_filtered":
		return "number of TCP6 SYN sent filtered packets"
	case "tcp6_syn_sent_fin_rcvd":
		return "number of TCP6 SYN sent FIN received packets"
	case "tcp6_syn_sent_invalid_connection":
		return "number of TCP6 SYN sent invalid connection packets"
	case "tcp6_syn_sent_length":
		return "number of TCP6 SYN sent length error packets"
	case "tcp6_syn_sent_link_local_rw":
		return "number of TCP6 SYN sent link local read/write packets"
	case "tcp6_syn_sent_lookup_drops":
		return "number of TCP6 SYN sent lookup drops packets"
	case "tcp6_syn_sent_msg_queue_full":
		return "number of TCP6 SYN sent packets dropped due to full message queue"
	case "tcp6_syn_sent_no_listener":
		return "number of TCP6 SYN sent no listener packets"
	case "tcp6_syn_sent_none":
		return "number of TCP6 SYN sent none packets"
	case "tcp6_syn_sent_options":
		return "number of TCP6 SYN sent options packets"
	case "tcp6_syn_sent_partially_enqueued":
		return "number of TCP6 SYN sent partially enqueued packets"
	case "tcp6_syn_sent_paws":
		return "number of TCP6 SYN sent PAWS packets"
	case "tcp6_syn_sent_pkts_sent":
		return "number of TCP6 SYN sent packets sent"
	case "tcp6_syn_sent_punt":
		return "number of TCP6 SYN sent punt packets"
	case "tcp6_syn_sent_rcv_wnd":
		return "number of TCP6 SYN sent receive window packets"
	case "tcp6_syn_sent_rst_rcvd":
		return "number of TCP6 SYN sent RST received packets"
	case "tcp6_syn_sent_rst_sent":
		return "number of TCP6 SYN sent RST sent packets"
	case "tcp6_syn_sent_segment_invalid":
		return "number of TCP6 SYN sent invalid segment packets"
	case "tcp6_syn_sent_segment_old":
		return "number of TCP6 SYN sent old segment packets"
	case "tcp6_syn_sent_spurious_syn":
		return "number of TCP6 SYN sent spurious SYN packets"
	case "tcp6_syn_sent_spurious_syn_ack":
		return "number of TCP6 SYN sent spurious SYN-ACK packets"
	case "tcp6_syn_sent_syn_acks_rcvd":
		return "number of TCP6 SYN sent SYN-ACK received packets"
	case "tcp6_syn_sent_syns_rcvd":
		return "number of TCP6 SYN sent SYN received packets"
	case "tcp6_syn_sent_wrong_thread":
		return "number of TCP6 SYN sent wrong thread packets"
	case "tcp6_syn_sent_zero_rwnd":
		return "number of TCP6 SYN sent zero receive window packets"
	default:
		return vppStatName
	}
}

func getVppSessionStatDescription(vppStatName string) string {
	switch cleanVppSessionStatName(vppStatName) {
	case "session_sessions_per_worker":
		return "number of sessions per worker"
	case "session_sessions_total":
		return "total number of sessions across all workers"
	case "transport_port_alloc_max_tries":
		return "number of attempts to allocate a transport port"
	default:
		return vppStatName
	}
}
