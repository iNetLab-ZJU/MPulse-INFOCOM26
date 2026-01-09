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
typedef bit<32>  reg_table_key_t;

typedef bit<8> reg_remote_state_t;
typedef bit<16> neighbor_alive_state_t;
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
    error_switch_t error_switch_0;
    error_switch_t error_switch_1;
    error_switch_t error_switch_2;
    error_switch_t error_switch_3;
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


parser SwitchIngressParser(
       packet_in packet, 
       out headers hdr, 
       out  ingress_metadata_t meta,
       out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        packet.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
     
    state parse_port_metadata {
        packet.advance(PORT_METADATA_SIZE);

        pktgen_port_down_header_t pktgen_pd_hdr = packet.lookahead<pktgen_port_down_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            2 : parse_pktgen_timer;
            4 : parse_pktgen_port_down;
            default : parse_ethernet;
        }
    }
    state  meta_init{
         meta.port_status.error_switch_0=0;
         meta.port_status.error_switch_1=0;
         meta.port_status.error_switch_2=0;
         meta.port_status.error_switch_3=0;
         transition parse_ethernet;
    }
    state parse_pktgen_port_down {
        packet.extract(hdr.port_down);
        transition meta_init;
    }


    state parse_pktgen_timer {
        packet.extract(hdr.timer);
        transition meta_init;
    }
    state parse_resubmit {
        packet.extract(meta.port_status);
        transition parse_pktgen_timer_resubmit;
    }
    state parse_pktgen_timer_resubmit {
        packet.extract(hdr.timer);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_HEARTBEAT : parse_heartbeat;
            ETHERTYPE_TPID :  parse_vlan_tag;
            ETHERTYPE_IPV4 :  parse_ipv4;
            default        :  accept;
        }
    }

    state parse_heartbeat {
        packet.extract(hdr.heartbeat);
        transition parse_neighbor_state;
    }
    state parse_neighbor_state {
        packet.extract(hdr.neighborState.next);
        transition select(hdr.neighborState.last.is_last) {
            1              :  parse_next;
            default        :  parse_neighbor_state_1;
        }
    }
    state parse_neighbor_state_1 {
        packet.extract(hdr.neighborState.next);
        transition select(hdr.neighborState.last.is_last) {
            1              :  parse_next;
            default        :  parse_neighbor_state_2;
        }
    }
    state parse_neighbor_state_2 {
        packet.extract(hdr.neighborState.next);
        transition select(hdr.neighborState.last.is_last) {
            1              :  parse_next;
            default        :  parse_neighbor_state_3;
        }
    }
    state parse_neighbor_state_3 {
        packet.extract(hdr.neighborState.next);
        transition select(hdr.neighborState.last.is_last) {
            1              :  parse_next;
            default        :  parse_neighbor_state_3;
        }
    }
    state parse_next{
        transition select(hdr.heartbeat.protocol) {
            ETHERTYPE_TPID :  parse_vlan_tag;
            ETHERTYPE_IPV4 :  parse_ipv4;
            default        :  accept;
        }
    }
    state parse_vlan_tag {
        packet.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4 :  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


control SwitchIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in  ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
        
    Digest<digest_t>() digest;
    Resubmit() resubmit;
    apply {
        // Generate a digest, if digest_type is set in MAU.
        if (ig_intr_dprsr_md.digest_type == 1) {
            // digest.pack({ig_md.signature,ig_md.alarm_info[0].port,ig_md.alarm_info[0].error_switch,ig_md.alarm_info[1].port,ig_md.alarm_info[1].error_switch,ig_md.alarm_info[2].port,ig_md.alarm_info[2].error_switch,ig_md.alarm_info[3].port,ig_md.alarm_info[3].error_switch});
            // digest.pack({ig_md.signature,ig_md.port_status.port_0,ig_md.port_status.error_switch_0,ig_md.port_status.port_1,ig_md.port_status.error_switch_1
            // ,
            // ig_md.port_status.port_2,ig_md.port_status.error_switch_2,ig_md.port_status.port_3,ig_md.port_status.error_switch_3
            // });
            digest.pack({ig_md.signature,
            ig_md.port_status.error_switch_0,
            ig_md.port_status.error_switch_1,
            ig_md.port_status.error_switch_2,
            ig_md.port_status.error_switch_3
            });
        }
        if(ig_intr_dprsr_md.resubmit_type==1){
            resubmit.emit(ig_md.port_status);
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.heartbeat);
        pkt.emit(hdr.neighborState);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

parser EgressParser(packet_in      pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

#include "pktgen_other194_5.p4"
#include "pktgen_other194_7.p4"


Pipeline(SwitchIngressParser(),
         SwitchIngress_7(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe_a;

Pipeline(SwitchIngressParser(),
         SwitchIngress_5(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe_b;
Switch(pipe_a,pipe_b) main;
