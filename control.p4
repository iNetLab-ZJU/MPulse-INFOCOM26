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

const state_t NOALIVE = 0x0;
const state_t ALIVE = 0x1;
const bit<32> node_num=13;
const bit<1> ACK = 0x0;
const bit<1> REPLY = 0x1;

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
        packet.advance(PORT_METADATA_SIZE);

        pktgen_port_down_header_t pktgen_pd_hdr = packet.lookahead<pktgen_port_down_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            2 : parse_pktgen_timer;
            default : parse_ethernet;
        }
    }
    state meta_init{
        
    }


    state parse_pktgen_timer {
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
            default        :  parse_neighbor_state;
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
    apply {
        // Generate a digest, if digest_type is set in MAU.
        if (ig_intr_dprsr_md.digest_type == 1) {
            // digest.pack({ig_md.signature,ig_md.alarm_info[0].port,ig_md.alarm_info[0].error_switch,ig_md.alarm_info[1].port,ig_md.alarm_info[1].error_switch,ig_md.alarm_info[2].port,ig_md.alarm_info[2].error_switch,ig_md.alarm_info[3].port,ig_md.alarm_info[3].error_switch});
            digest.pack({ig_md.signature,ig_md.port_0,ig_md.error_switch_0,ig_md.port_1,ig_md.error_switch_1,ig_md.port_2,ig_md.error_switch_2,ig_md.port_3,ig_md.error_switch_3});
        }
        pkt.emit(hdr);
    }
}

// control check_neighbor_alive(in Register<bit<32>, reg_table_key_t> neighbor_time_reg,
//                           in Register<bit<32>, reg_table_key_t> neighbor_state_reg,
//                           in signature_t Monitored_switch,inout state_t state) {
                            
//     RegisterAction<bit<32>, reg_table_key_t, bit<32>>(neighbor_time_reg) 
//     store_neighbor_time_reg_action = {
//         void apply(inout bit<32> value, out bit<32> read_value){
//             read_value = value;
//         }
//     };
//     apply {
//         store_neighbor_time_reg_action.execute(0);
//     }
    
    
// }
control SwitchIngress(
        inout headers hdr, 
        inout  ingress_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    bit<32> neighbor_list;
    state_t neighbor_own_state;
    state_t neighbot_control_state;
    bit<48> ingress_global_time;
    bit<32> ingress_global_time_1;
    bit<32> ingress_global_time_2;
    bit<32> ingress_global_time_3;
    bit<4> neighbor_0=0;
    bit<4> neighbor_1=0;
    bit<4> neighbor_2=0;
    bit<4> neighbor_3=0;
    neighbor_state_t state_0;
    neighbor_state_t state_1;
    neighbor_state_t state_2;
    neighbor_state_t state_3;
    PortId_t next_port;
    state_t next_port_state;
    reg_table_key_t reg_table_key;
    reg_key_half_t signature_Back = (reg_key_half_t) hdr.heartbeat.signature;
    reg_key_half_t Monitored_switch_Back = (reg_key_half_t) hdr.heartbeat.Monitored_switch;

    //the batch of the packets
    Register<bit<1>, bit<1>>(1) batch_time_reg;
    RegisterAction<bit<1>, bit<1>, bit<1>>(batch_time_reg) 
    catch_batch_time_reg_action = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value=value;
            value=1;
        }
    };
    //the table of neighbor alive state
    Register<time_t, reg_table_key_t>(reg_table_size) neighbor_time_reg;
    RegisterAction<time_t, reg_table_key_t, bit<1>>(neighbor_time_reg) 
    store_neighbor_time_reg_action = {
        void apply(inout time_t value){
            value.time_1 = (bit<32>)ingress_global_time[47:32];
            value.time_2 = ingress_global_time[31:0];
        }
    };
    //todo: check the time
    RegisterAction<time_t, reg_table_key_t,bit<1>>(neighbor_time_reg)
    check_neighbor_time_reg_action = {
        void apply(inout time_t value, out bit<1> read_value){
            if(value.time_1 == (bit<32>)ingress_global_time[47:32]){
                bit<32> ingress_global_time_dur = ingress_global_time[31:0]-value.time_2;
                if(ingress_global_time_dur>40){
                      read_value =1;
                }
            }
        }
    };

    //the table of neighbor id
    Register<bit<32>, reg_table_key_t>(node_num) neighbor_id_reg;
    RegisterAction<bit<32>, reg_table_key_t, bit<32>>(neighbor_id_reg) 
    store_neighbor_id_reg_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };
    RegisterAction<bit<32>, reg_table_key_t, bit<32>>(neighbor_id_reg) 
    read_neighbor_id_reg_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    //the table of neighbor alive state
    Register<state_t, reg_table_key_t>(reg_table_size) neighbor_alive_reg;
    RegisterAction<state_t, reg_table_key_t, state_t>(neighbor_alive_reg) 
    read_neighbor_alive_reg_action = {
        void apply(inout state_t value, out state_t read_value){
            read_value = value;
        }
    };
    RegisterAction<state_t, reg_table_key_t, state_t>(neighbor_alive_reg) 
    store_neighbor_alive_reg_action = {
        void apply(inout state_t value){
            value = ALIVE;
        }
    };

    RegisterAction<state_t, reg_table_key_t, state_t>(neighbor_alive_reg) 
    reset_neighbor_alive_reg_action = {
        void apply(inout state_t value){
            value = NOALIVE;
        }
    };

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }
    action change_port(PortId_t back_port) {
        ig_intr_tm_md.ucast_egress_port = back_port;
    }
    action l3_switch(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_port=port;
    }
    action heart_back_action() {
        hdr.heartbeat.setValid();    
        hdr.heartbeat.heartbeat_type = REPLY;
        hdr.heartbeat.state = ALIVE;
        ig_intr_tm_md.ucast_egress_port =  ig_intr_md.ingress_port;
    }
    action getNeighborList( reg_table_key_t  Monitored_switch){
        neighbor_list = read_neighbor_id_reg_action.execute( Monitored_switch);
    }

    action getNeighborState_0(){
        state_0=(neighbor_state_t)read_neighbor_alive_reg_action.execute((bit<8>) neighbor_0);
    }
    action getNeighborState_1(){
        state_1=(neighbor_state_t)read_neighbor_alive_reg_action.execute((bit<8>) neighbor_1);
    }
    action getNeighborState_2(){
        state_2=(neighbor_state_t)read_neighbor_alive_reg_action.execute((bit<8>) neighbor_2);
    }
    action getNeighborState_3(){
        state_3=(neighbor_state_t)read_neighbor_alive_reg_action.execute((bit<8>) neighbor_3);
    }
    action setNeighborState(reg_table_key_t reg_table_key){
        store_neighbor_alive_reg_action.execute(reg_table_key);
    }
    action setHeaderNeighborStateAll(){
        hdr.neighborState[0].state=state_0;
        hdr.neighborState[1].state=state_1;
        hdr.neighborState[2].state=state_2;
        hdr.neighborState[3].state=state_3;
    }

    action add_heartbeat(signature_t signature,signature_t Monitored_switch,bit<32> neighbor_state){
        hdr.heartbeat.setValid();
        hdr.heartbeat.heartbeat_type = ACK;
        //hdr.heartbeat.protocol = hdr.ethernet.ether_type;
        hdr.heartbeat.signature = signature;
        hdr.ethernet.ether_type = ETHERTYPE_HEARTBEAT;
        hdr.heartbeat.Monitored_switch = Monitored_switch;
        //   hdr.neighborState.setValid();
        neighbor_0=neighbor_list[3:0];
        neighbor_1=neighbor_list[7:4];
        neighbor_2=neighbor_list[11:8];
        neighbor_3=neighbor_list[15:12];
        hdr.neighborState[0].neighbor=neighbor_0;
        hdr.neighborState[1].neighbor=neighbor_1;
        hdr.neighborState[2].neighbor=neighbor_2;
        hdr.neighborState[3].neighbor=neighbor_3;
        hdr.heartbeat.state = 0;
    }

    action reset_register_action(){
          reset_neighbor_alive_reg_action.execute(reg_table_key);
    }


    action match(PortId_t port,signature_t signature,signature_t Monitored_switch,bit<32> neighbor_state) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_port=port;
        Monitored_switch_Back = (reg_key_half_t)Monitored_switch;
        signature_Back = (reg_key_half_t)signature;
        getNeighborList((reg_table_key_t)Monitored_switch);
        add_heartbeat(signature,Monitored_switch,neighbor_state);
    }
    // action receive_heartbeat_action(MulticastGroupId_t mcast_grp_id) {
    //         store_neighbor_alive_reg_action.execute(reg_table_key);
    //         // ig_intr_tm_md.mcast_grp_a = mcast_grp_id;
    // }
    action receive_heartbeat_action() {
            store_neighbor_alive_reg_action.execute(reg_table_key);
            // ig_intr_tm_md.mcast_grp_a = mcast_grp_id;
    }
    action carry_to_digest_0(signature_t error_switch){
        // md.port=next_port;
        md.signature=(signature_t)signature_Back;
        // md.error_switch= error_switch;
        md.port_0=next_port;
        md.error_switch_0= error_switch;
    }
    action carry_to_digest_1(signature_t error_switch){
        // md.port=next_port;
        md.signature=(signature_t)signature_Back;
        // md.error_switch= error_switch;
        md.port_1=next_port;
        md.error_switch_1= error_switch;
    }
    action carry_to_digest_2(signature_t error_switch){
        // md.port=next_port;
        md.signature=(signature_t)signature_Back;
        // md.error_switch= error_switch;
        md.port_2=next_port;
        md.error_switch_2= error_switch;
    }
    action carry_to_digest_3(signature_t error_switch){
        // md.port=next_port;
        md.signature=(signature_t)signature_Back;
        // md.error_switch= error_switch;
        md.port_3=next_port;
        md.error_switch_3= error_switch;
    }

    ///
    action receive_mulicast_action() {
            store_neighbor_alive_reg_action.execute(reg_table_key);
            drop();
    }
    ///

    //@idletime_precision(3)
    table receive_heartbeat {
        key={
             hdr.heartbeat.heartbeat_type : exact;
             hdr.heartbeat.Monitored_switch : exact;
             hdr.heartbeat.signature : exact;
        }
        actions ={
             receive_heartbeat_action;//暂定其是单独的，不与发包相关
             @defaultonly NoAction;
        }
        const default_action = NoAction();
        //idle_timeout = true;
        size = 1024;
    }

    ///
    table receive_mulicast {
        key={
             hdr.heartbeat.heartbeat_type : exact;
        }
        actions ={
             receive_mulicast_action;
             @defaultonly drop;
        }
        const default_action = drop();
        //idle_timeout = true;
        size = 1024;
    }
    ///

    table timer_periodic {
        key = {
            hdr.timer.pipe_id : exact;
            hdr.timer.app_id  : exact;
            hdr.timer.batch_id : exact;
            hdr.timer.packet_id : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            match;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    table heart_back {
        key = {
            hdr.heartbeat.heartbeat_type : exact;
            hdr.heartbeat.Monitored_switch : exact;
        }
        actions = {
            heart_back_action;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }
    table change_port_table{
        key = {
            next_port:  exact;
            next_port_state:   exact;
        }
        actions = {
            change_port;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table forward_table{
        key = { 
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr: ternary;
            // trans_port: exact;
            ig_intr_md.ingress_port: exact; 
        }
        actions = {
            drop; 
            l3_switch;
            NoAction;
        }

        size = 1024;
        const default_action = drop();
    }
    apply {
        //record the timestamp
        ingress_global_time= ig_intr_prsr_md.global_tstamp;
        ingress_global_time_1= (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
        ingress_global_time_2= ig_intr_prsr_md.global_tstamp[31:0];
        if (hdr.timer.isValid()) {
            //同时将心跳包发给对应的交换机
            timer_periodic.apply();
            //第一组数据包不读状态？
            bit<1> batch_time = catch_batch_time_reg_action.execute(0);
            if(batch_time==0){
                hdr.neighborState[0].state=1;
                hdr.neighborState[1].state=1;
                hdr.neighborState[2].state=1;
                hdr.neighborState[3].state=1;
            }else{
                //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机
                getNeighborState_0();
                getNeighborState_1();
                getNeighborState_2();
                getNeighborState_3();
                setHeaderNeighborStateAll();
                if(neighbor_0!=0 && (bit<1>)state_0==NOALIVE){
                    carry_to_digest_0((bit<7>)neighbor_0);
                    ig_intr_dprsr_md.digest_type = 1;
                }
                if(neighbor_1!=0 && (bit<1>)state_1==NOALIVE){
                    carry_to_digest_1((bit<7>)neighbor_1);
                    ig_intr_dprsr_md.digest_type = 1;
                }
                if(neighbor_2!=0 && (bit<1>)state_2==NOALIVE){
                    carry_to_digest_2((bit<7>)neighbor_2);
                    ig_intr_dprsr_md.digest_type = 1;
                }
                if(neighbor_3!=0 && (bit<1>)state_3==NOALIVE){
                    carry_to_digest_3((bit<7>)neighbor_3);
                    ig_intr_dprsr_md.digest_type = 1;
                }
            }

            reg_table_key =(reg_table_key_t) Monitored_switch_Back ;
            store_neighbor_time_reg_action.execute((bit<8>)Monitored_switch_Back);
            reset_register_action();
        } else if(hdr.heartbeat.isValid()){
            signature_Back        = (reg_key_half_t) hdr.heartbeat.signature;
            Monitored_switch_Back = (reg_key_half_t) hdr.heartbeat.Monitored_switch;
            reg_table_key =(reg_table_key_t)hdr.heartbeat.Monitored_switch;
            if(hdr.heartbeat.heartbeat_type == ACK){
                heart_back.apply();
            }else if(hdr.heartbeat.heartbeat_type == REPLY){   
                setNeighborState(reg_table_key);
            }
            // else {
            //     if(!receive_heartbeat.apply().hit){
            //         receive_mulicast.apply();
            //     }
            // }
        }else{
            //normal forwarding
            forward_table.apply();
            next_port_state=read_neighbor_alive_reg_action.execute((bit<8>)next_port);

            if(next_port_state == NOALIVE){
                ig_intr_dprsr_md.digest_type = 1;
                change_port_table.apply();
            }else if(next_port_state == ALIVE){
                
            }
        }
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

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe;

Switch(pipe) main;
