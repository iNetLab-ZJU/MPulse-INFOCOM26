/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
 
#include "common/headers.p4"
#include "common/util.p4"
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
    // PortId_t port_2;
    // signature_t error_switch_2;
    // PortId_t port_3;
    // signature_t error_switch_3;
}
struct headers {
    pktgen_timer_header_t timer;
    pktgen_port_down_header_t port_down;
    ethernet_h         ethernet;
    heartbeat_t  heartbeat; 
    neighborList[2] neighborState;
    vlan_tag_h         vlan_tag;
    ipv4_h             ipv4;
}
    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

#include "pktgen-c.p4"
#include "pktgen-control.p4"


Pipeline(SwitchIngressParser_c(),
         SwitchIngress_c(),
         SwitchIngressDeparser_c(),
         EgressParser_c(),
         Egress_c(),
         EgressDeparser_c()) pipe_a;

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe_b;
Switch(pipe_a,pipe_b) main;
