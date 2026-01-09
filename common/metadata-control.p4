
#ifndef _HEADERS_
#define _HEADERS_

const bit<16> ETHERTYPE_TPID = 0x8100;

typedef bit<16> tcpPort_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  egressSpec_t;
typedef bit<4>  reg_key_half_t;
typedef bit<8>  reg_table_key_t;

typedef bit<8> reg_remote_state_t;
const register_state_t NOALIVE = 0x0;
const register_state_t ALIVE = 0x1;
const bit<32> node_num=13;
const bit<1> ACK = 0x0;
const bit<1> REPLY = 0x1;
const bit<32> time_duration_threshold=1200;
const bit<32> reg_table_size = 256;  

struct digest_t {
    signature_t signature;
    // alarm_info_t[4] alarm_info;
    PortId_t port_0;
    signature_t error_switch_0;
    PortId_t port_1;
    signature_t error_switch_1;
    PortId_t port_2;
    signature_t error_switch_2;
    PortId_t port_3;
    signature_t error_switch_3;
}
struct headers {
    pktgen_timer_header_t timer;
    pktgen_port_down_header_t port_down;
    ethernet_h         ethernet;
    heartbeat_t  heartbeat; 
    neighborList[4] neighborState;
    vlan_tag_h         vlan_tag;
    ipv4_h             ipv4;
}

#endif /* _HEADERS_ */
