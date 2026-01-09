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
    PortId_t port_0;
    error_switch_t error_switch_0;
    PortId_t port_1;
    error_switch_t error_switch_1;
    PortId_t port_2;
    error_switch_t error_switch_2;
    PortId_t port_3;
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
         meta.port_status.port_0=0;
         meta.port_status.port_1=0;
         meta.port_status.port_2=0;
         meta.port_status.port_3=0;
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
control getRegister(
    in reg_table_key_t key,
    in Register<time_t, reg_table_key_t> neighbor_time_reg,
    in Register<time_t, reg_table_key_t> neighbor_alive_reg
){
    reg_table_key_t key1;
    apply {
        key1 = key;
        neighbor_time_reg.read(key1);
        neighbor_alive_reg.read(key1);
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
            digest.pack({ig_md.signature,ig_md.port_status.port_0,ig_md.port_status.error_switch_0,ig_md.port_status.port_1,ig_md.port_status.error_switch_1
            ,
            ig_md.port_status.port_2,ig_md.port_status.error_switch_2,ig_md.port_status.port_3,ig_md.port_status.error_switch_3
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


control SwitchIngress(
        inout headers hdr, 
        inout  ingress_metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    bit<32> neighbor_list=0;
    bit<4> flag=0;
    bit<48> ingress_global_time=0;
    bit<32> ingress_global_time_1;
    bit<32> ingress_global_time_2;
    bit<8> flow_id;
    bit<2> pipe;
    bit<4> neighbor_num=4;
    bit<4> neighbor_0=0;
    bit<4> neighbor_1=0;
    bit<4> neighbor_2=0;
    bit<4> neighbor_3=0;
    bit<1> ifTimeOut_0=0;
    bit<1> ifTimeOut_1=0;
    bit<1> ifTimeOut_2=0;
    bit<1> ifTimeOut_3=0;
    reg_table_key_t neighbor0=0;
    reg_table_key_t neighbor1=0;
    reg_table_key_t neighbor2=0;
    reg_table_key_t neighbor3=0;
    bit<32> down_time_count=0;
    bit<1> alive_flag=0;
    bit<4>  neighbor_count=0;
    bit<4>  neighbor_count_2=0;
    register_state_t store_state=0;
    bit<1> timeout_0=0;
    bit<1> timeout_1=0;
    bit<1> timeout_2=0;
    bit<1> timeout_3=0;
    bit<1> timeout_4=0;
    bit<1> timeout_5=0;
    bit<1> timeout_6=0;
    bit<1> timeout_7=0;
    bit<1> timeout_8=0;
    bit<1> timeout_9=0;
    bit<1> timeout_10=0;
    bit<1> timeout_11=0;
    
    register_state_t state0=0;
    register_state_t state1=0;
    register_state_t state2=0;
    register_state_t state3=0;
    register_state_t state4=0;
    register_state_t state5=0;
    register_state_t state6=0;
    register_state_t state7=0;
    register_state_t state8=0;
    register_state_t state9=0;
    register_state_t state10=0;
    register_state_t state11=0;

    // register_state_t state0=0;
    // register_state_t state1=0;
    // register_state_t state2=0;
    // register_state_t state3=0;
    register_state_t stateM=0;
    // register_state_t stateM_2=0;
    reg_remote_state_t reg_remote_state=0;
    
    neighbor_state_t stateh0=0;
    neighbor_state_t stateh1=0;
    neighbor_state_t stateh2=0;
    neighbor_state_t stateh3=0;

    PortId_t next_Switch=0;
    register_state_t next_Switch_state=0;
    register_state_t next_Switch_state1=0;
    register_state_t next_Switch_state2=0;
    register_state_t next_Switch_state3=0;
    register_state_t next_switch_stateAll=0;
    bit<1> timeout_next_Switch=0;
    bit<1> timeout_next_Switch1=0;
    bit<1> timeout_next_Switch2=0;
    bit<1> timeout_next_Switch3=0;


    PortId_t next_port=0;
    register_state_t next_port_state=0;
    register_state_t next_port_stateAll=0;
    bit<1> timeout_next_port=0;

    PortId_t replace_port=0;
    reg_table_key_t reg_table_key=0;
    reg_table_key_t signatureNow=0;
    // reg_table_key_t Monitored_=0switch_now;
    reg_key_half_t signature_Back=0;
    reg_table_key_t Monitored_switch_now=0;
    //the batch of the packets,the first batch to init the packets
    Register<bit<1>, reg_table_key_t>(node_num) batch_time_reg;
    RegisterAction<bit<1>, reg_table_key_t, bit<1>>(batch_time_reg) 
    catch_batch_time_reg_action = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value=value;
            value=1;
        }
    };
    Register<time_t, reg_table_key_t>(reg_table_size) port_down_time_reg;
    RegisterAction<time_t, reg_table_key_t, bit<1>>(port_down_time_reg) 
    store_port_down_time_reg_action = {
        void apply(inout time_t value){
            value.time_1 = ingress_global_time_1;
            value.time_2 = ingress_global_time_2;
        }
    };
    RegisterAction<time_t, reg_table_key_t,bit<1>>(port_down_time_reg)
    check_port_down_time_reg_action = {
        void apply(inout time_t value, out bit<1> read_value){
            if(value.time_1 == (bit<32>)ingress_global_time_1){
                bit<32> ingress_global_time_dur = ingress_global_time_2-value.time_2;
                if(ingress_global_time_dur>time_duration_threshold){
                      read_value =1;
                }
            }
        }
    };
 
    //the table of neighbor alive state (key-states)

#define GEN_REGISTER_TIME(n)                                                        \
    Register<time_t, reg_table_key_t>(node_num) neighbor_time_##n##_reg;            \
    RegisterAction<time_t, reg_table_key_t, bit<1>>(neighbor_time_##n##_reg)        \
    store_neighbor_time_##n##_reg_action = {                                        \
        void apply(inout time_t value){                                             \
                value.time_1 = (bit<32>)ingress_global_time[47:32];                 \
                value.time_2 = ingress_global_time[31:0];                           \
        }                                                                           \
    };                                                                              \
    RegisterAction<time_t, reg_table_key_t,bit<1>>(neighbor_time_##n##_reg)         \
    check_neighbor_time_##n##_reg_action = {                                        \
        void apply(inout time_t value, out bit<1> read_value){                      \
            if(value.time_1 == (bit<32>)ingress_global_time[47:32]){                \
                bit<32> ingress_global_time_dur = ingress_global_time[31:0]-value.time_2;   \
                if(ingress_global_time_dur>time_duration_threshold){    \
                    read_value =1;  \
                }else{  \
                    read_value=0;   \
                }   \
            }else{  \
                read_value=1;   \
            }   \
        }   \
    };

    GEN_REGISTER_TIME(1)
    GEN_REGISTER_TIME(2)
    GEN_REGISTER_TIME(3)
    GEN_REGISTER_TIME(4)
    GEN_REGISTER_TIME(5)
    GEN_REGISTER_TIME(6)
    GEN_REGISTER_TIME(7)
    GEN_REGISTER_TIME(8)
    GEN_REGISTER_TIME(9)
    GEN_REGISTER_TIME(10)
    GEN_REGISTER_TIME(11)


        //the table of neighbor alive state
#define GEN_NEIGHBOR_STATE_REGISTER(n)  \    
    Register<register_state_t, reg_table_key_t>(node_num) neighbor_alive_reg_##n##; \
    RegisterAction<register_state_t, reg_table_key_t, register_state_t>(neighbor_alive_reg_##n##) \
    read_neighbor_alive_reg_##n##_action = {\
        void apply(inout register_state_t value, out register_state_t read_value){\
            read_value = value;     \
        }\
    };\
    RegisterAction<register_state_t, reg_table_key_t, register_state_t>(neighbor_alive_reg_##n##) \
    store_neighbor_alive_reg_##n##_action = {   \
        void apply(inout register_state_t value){\
            if(store_state==0){\
                value=NOALIVE;\
            }else{\
                value=ALIVE;\
            }\
        }\
    };\

    GEN_NEIGHBOR_STATE_REGISTER(1)
    GEN_NEIGHBOR_STATE_REGISTER(2)
    GEN_NEIGHBOR_STATE_REGISTER(3)
    GEN_NEIGHBOR_STATE_REGISTER(4)
    GEN_NEIGHBOR_STATE_REGISTER(5)
    GEN_NEIGHBOR_STATE_REGISTER(6)
    GEN_NEIGHBOR_STATE_REGISTER(7)
    GEN_NEIGHBOR_STATE_REGISTER(8)
    GEN_NEIGHBOR_STATE_REGISTER(9)
    GEN_NEIGHBOR_STATE_REGISTER(10)
    GEN_NEIGHBOR_STATE_REGISTER(11)

    Register<time_t, reg_table_key_t>(12) neighbor_time_reg;
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
                if(ingress_global_time_dur>time_duration_threshold){
                    read_value =1; // timeout 
                }else{
                    read_value=0;
                }
            }else{
                read_value=1;
            }
        }
    };


    //the table of neighbor id
    Register<bit<32>, reg_table_key_t>(node_num) neighbor_id_reg;
    RegisterAction<bit<32>, reg_table_key_t, bit<32>>(neighbor_id_reg) 
    read_neighbor_id_reg_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };
    //the table of next_port
    // Register<bit<32>, reg_table_key_t>(node_num) next_port_reg;
    // RegisterAction<bit<32>, reg_table_key_t, bit<32>>(next_port_reg) 
    // read_next_port_reg_action = {
    //     void apply(inout bit<32> value, out bit<32> read_value){
    //         read_value = value;
    //     }
    // };
        //the table of reback time
    Register<bit<32>, reg_table_key_t>(node_num) down_time_id_reg;
    RegisterAction<bit<32>, reg_table_key_t, bit<32>>(down_time_id_reg) 
    down_time_id_reg_action = {
        void apply(inout bit<32> value,out bit<32> read_value){
            if(value==65534){
                value=value;
            }else{
                value=value+1;
            }
            read_value = value;
        }
    };
    // check the time
    Register<time_t, bit<32>>(65535) down_time_reg;
    RegisterAction<time_t, bit<32>, bit<1>>(down_time_reg) 
    store_down_time_reg_action = {
        void apply(inout time_t value){
            value.time_1 = (bit<32>)ingress_global_time[47:32];
            value.time_2 = ingress_global_time[31:0];
        }
    };
 

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action change_port(PortId_t back_port) {
        ig_intr_tm_md.ucast_egress_port = back_port;
    }
    action l3_switch(PortId_t port,PortId_t nextSwitchId) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_Switch=nextSwitchId;
    }
    
    action getNeighborList( reg_table_key_t  Monitored_switch){
        neighbor_list = read_neighbor_id_reg_action.execute( Monitored_switch);
    }


    action setHeaderState_0(){
         hdr.neighborState[0].state=1;
    }
    action setHeaderState_1(){
         hdr.neighborState[1].state=1;
    }
    action setHeaderState_2(){
        hdr.neighborState[2].state=1;
    }
    action setHeaderState_3(){
        hdr.neighborState[3].state=1;
    }
    action heart_back_action() {
        hdr.heartbeat.setValid();    
        hdr.heartbeat.heartbeat_type = REPLY;
        ig_intr_tm_md.ucast_egress_port =  ig_intr_md.ingress_port;
    }



    action add_heartbeat(signature_t signature,signature_t Monitored_switch){
        hdr.heartbeat.setValid();
        hdr.heartbeat.heartbeat_type = ACK;
        //hdr.heartbeat.protocol = hdr.ethernet.ether_type;
        hdr.heartbeat.signature = signature;
        hdr.ethernet.ether_type = ETHERTYPE_HEARTBEAT;
        hdr.heartbeat.Monitored_switch = Monitored_switch;
        neighbor_0=neighbor_list[3:0];
        neighbor_1=neighbor_list[7:4];
        neighbor_2=neighbor_list[11:8];
        neighbor_3=neighbor_list[15:12];
        // get_neighbor_id_totalLength();
        hdr.neighborState[0].neighbor=neighbor_0;
        hdr.neighborState[1].neighbor=neighbor_1;
        hdr.neighborState[2].neighbor=neighbor_2;
        hdr.neighborState[3].neighbor=neighbor_3;
        // hdr.heartbeat.state = 0;
    }

    action match(PortId_t port,signature_t signature,signature_t Monitored_switch) {
        ig_intr_tm_md.ucast_egress_port = port;
        signatureNow = (reg_table_key_t)signature;
        // Monitored_switch_now=(reg_table_key_t)Monitored_switch;
        getNeighborList((reg_table_key_t)Monitored_switch);
        add_heartbeat(signature,Monitored_switch);
    }
    action match_consensus(PortId_t port,signature_t signature,signature_t Monitored_switch,bit<32> trans_neighbor_alive_list) {
        ig_intr_tm_md.ucast_egress_port = port;
        signatureNow = (reg_table_key_t)signature;
        neighbor_list = trans_neighbor_alive_list;
        add_heartbeat(signature,Monitored_switch);
    }
    action match_down(PortId_t port,signature_t signature,signature_t Monitored_switch) {
        ig_intr_tm_md.ucast_egress_port = port;
        // next_port=port;
        // Monitored_switch_Back = (reg_key_half_t)Monitored_switch;
        signature_Back = (reg_key_half_t)signature;
        add_heartbeat(signature,Monitored_switch);
        hdr.heartbeat.state = 1;
    }
    
    action carry_to_digest_0(){
        meta.port_status.port_0=1;
        meta.port_status.error_switch_0= (error_switch_t)neighbor_0;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_1(){
        meta.port_status.port_1=1;
        meta.port_status.error_switch_1= (error_switch_t)neighbor_1;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_2(){
        meta.port_status.port_2=1;
        meta.port_status.error_switch_2= (error_switch_t)neighbor_2;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_3(){
        meta.port_status.port_3=1;
        meta.port_status.error_switch_3= (error_switch_t)neighbor_3;
        ig_intr_dprsr_md.digest_type =1;
    }
    action getResubmit(){
        neighbor0=(reg_table_key_t)meta.port_status.error_switch_0;
        neighbor1=(reg_table_key_t)meta.port_status.error_switch_1;
        neighbor2=(reg_table_key_t)meta.port_status.error_switch_2;
        neighbor3=(reg_table_key_t)meta.port_status.error_switch_3;
    }

    action init_header_state(){
        hdr.neighborState[0].state=1;
        hdr.neighborState[1].state=1;
        hdr.neighborState[2].state=1;
        hdr.neighborState[3].state=1;
    }
    action get_neighbor_id_and_state(){
        neighbor0=(reg_table_key_t)hdr.neighborState[0].neighbor;
        neighbor1=(reg_table_key_t)hdr.neighborState[1].neighbor;
        neighbor2=(reg_table_key_t)hdr.neighborState[2].neighbor;
        neighbor3=(reg_table_key_t)hdr.neighborState[3].neighbor;
        state0=(register_state_t)hdr.neighborState[0].state;
        state1=(register_state_t)hdr.neighborState[1].state;
        state2=(register_state_t)hdr.neighborState[2].state;
        state3=(register_state_t)hdr.neighborState[3].state;
    }
    action getRegisterKeySignature(){
        reg_table_key=(reg_table_key_t) hdr.heartbeat.signature;
    }
    action getRegisterKeyMoniter(){
        reg_table_key = (reg_table_key_t) hdr.heartbeat.Monitored_switch;
    }
#define STORE_MONITERED_ALIVE_REG_ACTION_X(x,n)\
        if (neighbor##x##!=0){     \
            store_state=state##x##;\
            @stage(5)\
            {\
                store_neighbor_alive_reg_##n##_action.execute(neighbor##x##);\
            }       \ 
            @stage(6){\
                store_neighbor_time_##n##_reg_action.execute(neighbor##x##);\
            }\
            if(state##x##==0){  \
                carry_to_digest_##x##();       \
            }\
        }\
// reg_table_key_t neighbor=(reg_table_key_t)neighbor_##x##;    
#define STORE_MONITERED_ALIVE_REG_ACTION(n)\
            @stage(5)\
            {\
                store_neighbor_alive_reg_##n##_action.execute(reg_table_key);\
            }\
            @stage(6){\
                store_neighbor_time_##n##_reg_action.execute(reg_table_key);\
            }
            

#define GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(x,n)      \
        if (neighbor_##x##!=0){     \
            neighbor##x##=(reg_table_key_t)neighbor_##x##;\
            @stage(5){\
                state##x## =read_neighbor_alive_reg_##n##_action.execute(neighbor##x##);\
            }\
            @stage(6){\
                timeout_##x##=check_neighbor_time_##n##_reg_action.execute(neighbor##x##);\
            }\
            @stage(7){if(timeout_##x##==1 && state##x##==0){  \
                carry_to_digest_##x##();       \
            }else{  \
                setHeaderState_##x##();   \
            }   \
            }\
        }

    table port_down_table {
        key = {
            hdr.port_down.pipe_id   : exact;
            hdr.port_down.app_id    : exact;
            hdr.port_down.port_num  : exact;
            hdr.port_down.packet_id : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            match_down;
            @defaultonly drop;
        }
        //const default_action = NoAction();
        size = 1024;
    }

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
            match_consensus;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    table getKey_table{
        key={
            hdr.heartbeat.heartbeat_type:exact;
        }
        actions={
            getRegisterKeySignature;
            getRegisterKeyMoniter;
        }
        const entries = {
            (ACK):getRegisterKeySignature;
            (REPLY):getRegisterKeyMoniter;
        }
        size=8;

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
            // flow_id:exact;
            next_Switch:  exact;
        }
        actions = {
            change_port;
            drop;
            NoAction;
        }
        size = 32;
        default_action = NoAction();
    }

    table forward_table{
        key = { 
            // hdr.ipv4.src_addr : ternary;
            // hdr.ipv4.dst_addr: ternary;
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
        pipe = ig_intr_md.ingress_port[8:7];
        if(ig_intr_md.resubmit_flag==0){
            //This is the first pass of the ingress pipeline for this packet.
            //if is timer packets
            if (hdr.timer.isValid()) {
                //同时将心跳包发给对应的交换机 init the intial information
                timer_periodic.apply();
                //被监测的交换机
                reg_table_key = (reg_table_key_t)hdr.heartbeat.Monitored_switch;
                //第一组数据包不读状态？
                bit<1> batch_time = catch_batch_time_reg_action.execute((reg_table_key_t)hdr.heartbeat.Monitored_switch);
                if(batch_time==0){
                    //初始各个邻居状态为1
                    init_header_state();
                    // stateM_2=1;
                    // @stage(4){store_neighbor_time_reg_action.execute(reg_table_key);}
                    //在本地检测寄存器中初始存储被检测节点的时间
                    if(signatureNow==1){
                        store_neighbor_time_1_reg_action.execute(reg_table_key);
                    }else if(signatureNow==2){
                        store_neighbor_time_2_reg_action.execute(reg_table_key);
                    }else if(signatureNow==3){
                        store_neighbor_time_3_reg_action.execute(reg_table_key);
                    }else if(signatureNow==4){
                        store_neighbor_time_4_reg_action.execute(reg_table_key);
                    }else if(signatureNow==5){
                        store_neighbor_time_5_reg_action.execute(reg_table_key);
                    }else if(signatureNow==6){
                        store_neighbor_time_6_reg_action.execute(reg_table_key);
                    }else if(signatureNow==7){
                        store_neighbor_time_7_reg_action.execute(reg_table_key);
                    }else if(signatureNow==8){
                        store_neighbor_time_8_reg_action.execute(reg_table_key);
                    }else if(signatureNow==9){
                        store_neighbor_time_9_reg_action.execute(reg_table_key);
                    }else if(signatureNow==10){
                        store_neighbor_time_10_reg_action.execute(reg_table_key);
                    }
                }else if (hdr.port_down.isValid()){
                    port_down_table.apply();
                    reg_table_key =  (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                    store_port_down_time_reg_action.execute(reg_table_key);
                }else if (batch_time==1){
                    //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机
                    meta.signature=(signature_t)signatureNow;                
                    store_state=0;
                    //store the monitered switch's state
                    if(signatureNow==1){
                        STORE_MONITERED_ALIVE_REG_ACTION(1);
                    }else if(signatureNow==2){
                        STORE_MONITERED_ALIVE_REG_ACTION(2);
                    }else if(signatureNow==3){
                        STORE_MONITERED_ALIVE_REG_ACTION(3);
                    }else if(signatureNow==4){
                        STORE_MONITERED_ALIVE_REG_ACTION(4);
                    }else if(signatureNow==5){
                        STORE_MONITERED_ALIVE_REG_ACTION(5);
                    }else if(signatureNow==6){
                        STORE_MONITERED_ALIVE_REG_ACTION(6);
                    }else if(signatureNow==7){
                        STORE_MONITERED_ALIVE_REG_ACTION(7);
                    }else if(signatureNow==8){
                        STORE_MONITERED_ALIVE_REG_ACTION(8);
                    }else if(signatureNow==9){
                        STORE_MONITERED_ALIVE_REG_ACTION(9);
                    }else if(signatureNow==10){
                        STORE_MONITERED_ALIVE_REG_ACTION(10);
                    }
                    
                    //to resubmit the packet
                    ig_intr_dprsr_md.resubmit_type = 1;
                }
            } else if(hdr.heartbeat.isValid()){
                if(hdr.heartbeat.state==1){
                    neighbor_1 = (bit<4>) hdr.heartbeat.signature;
                    carry_to_digest_1();
                    drop();
                }else {
                    getKey_table.apply();
                    if(hdr.heartbeat.heartbeat_type==ACK){
                        //reback the packets
                        // heart_back.apply();
                        //收到ACK数据包
                        store_state=1;
                        if(signatureNow==1){
                            STORE_MONITERED_ALIVE_REG_ACTION(1);
                        }else if(signatureNow==2){
                            STORE_MONITERED_ALIVE_REG_ACTION(2);
                        }else if(signatureNow==3){
                            STORE_MONITERED_ALIVE_REG_ACTION(3);
                        }else if(signatureNow==4){
                            STORE_MONITERED_ALIVE_REG_ACTION(4);
                        }else if(signatureNow==5){
                            STORE_MONITERED_ALIVE_REG_ACTION(5);
                        }else if(signatureNow==6){
                            STORE_MONITERED_ALIVE_REG_ACTION(6);
                        }else if(signatureNow==7){
                            STORE_MONITERED_ALIVE_REG_ACTION(7);
                        }else if(signatureNow==8){
                            STORE_MONITERED_ALIVE_REG_ACTION(8);
                        }else if(signatureNow==9){
                            STORE_MONITERED_ALIVE_REG_ACTION(9);
                        }else if(signatureNow==10){
                            STORE_MONITERED_ALIVE_REG_ACTION(10);
                        }
                        get_neighbor_id_and_state();
                    // STORE_MONITERED_ALIVE_REG_ACTION_X(x,n)  

                        if(hdr.heartbeat.signature==1){
                                // state_1=0;
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,1);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,1);
                        }else if(hdr.heartbeat.signature == 2){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,2);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,2);
                        }else if(hdr.heartbeat.signature == 3){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,3);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,3);
                        }else if(hdr.heartbeat.signature == 4){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,4);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,4);
                        }else if(hdr.heartbeat.signature == 5){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,5);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,5);
                        }else if(hdr.heartbeat.signature == 6){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,6);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,6);
                        }else if(hdr.heartbeat.signature == 7){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,7);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,7);
                        }else if(hdr.heartbeat.signature == 8){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,8);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,8);
                        }else if(hdr.heartbeat.signature == 9){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,9);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,9);
                        }else if(hdr.heartbeat.signature == 10){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,10);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,10);
                        }else if(hdr.heartbeat.signature == 11){
                                STORE_MONITERED_ALIVE_REG_ACTION_X(0,11);
                                STORE_MONITERED_ALIVE_REG_ACTION_X(1,11);
                        }
                        ig_intr_dprsr_md.resubmit_type = 1;
                    }else{
                        //get the reback packets
                         store_state=1;
                        //  STORE_MONITERED_ALIVE_REG_ACTION(11);
                         if(signatureNow==1){
                            STORE_MONITERED_ALIVE_REG_ACTION(1);
                        }else if(signatureNow==2){
                            STORE_MONITERED_ALIVE_REG_ACTION(2);
                        }else if(signatureNow==3){
                            STORE_MONITERED_ALIVE_REG_ACTION(3);
                        }else if(signatureNow==4){
                            STORE_MONITERED_ALIVE_REG_ACTION(4);
                        }else if(signatureNow==5){
                            STORE_MONITERED_ALIVE_REG_ACTION(5);
                        }else if(signatureNow==6){
                            STORE_MONITERED_ALIVE_REG_ACTION(6);
                        }else if(signatureNow==7){
                            STORE_MONITERED_ALIVE_REG_ACTION(7);
                        }else if(signatureNow==8){
                            STORE_MONITERED_ALIVE_REG_ACTION(8);
                        }else if(signatureNow==9){
                            STORE_MONITERED_ALIVE_REG_ACTION(9);
                        }else if(signatureNow==10){
                            STORE_MONITERED_ALIVE_REG_ACTION(10);
                        }
                        drop();
                    }
                    //to store the state of 
                   
                }
            }else{
                //normal forwarding
                forward_table.apply();
                // bit<9> ingress_port=ig_intr_md.ingress_port;
                reg_table_key_t key1=(reg_table_key_t)next_Switch;
                //from the detection switch
                next_Switch_state1 =read_neighbor_alive_reg_11_action.execute(key1);
                timeout_next_Switch1 =check_neighbor_time_11_reg_action.execute(key1);

                //from itself
                if(pipe==0){
                     next_Switch_state1 =read_neighbor_alive_reg_1_action.execute(key1);
                     timeout_next_Switch1 =check_neighbor_time_1_reg_action.execute(key1);
                }else{
                     next_Switch_state1 =read_neighbor_alive_reg_3_action.execute(key1);
                     timeout_next_Switch1 =check_neighbor_time_3_reg_action.execute(key1);
                }
               
                next_Switch_state=next_Switch_state1+next_Switch_state2;
                if(timeout_next_Switch1==1 && timeout_next_Switch2==1 &&next_Switch_state==0){  
                    change_port_table.apply();
                }
            }
        }else{
            // This is the second pass of the ingress pipeline for this packet.
            // ingress_global_time= ig_intr_prsr_md.global_tstamp;
            //if is timer packets
            if (hdr.timer.isValid()) {
                //被监测的交换机
                reg_table_key = (reg_table_key_t)hdr.heartbeat.Monitored_switch;
                    //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机
                    meta.signature=(signature_t)signatureNow;                
                    store_state=0;
                    //store the monitered switch's state
                    // store_neighbor_alive_reg_action.execute(reg_table_key);
                    // store_neighbor_time_reg_action.execute(reg_table_key);
                    //get the monitered switch's neighbors state
                if(reg_table_key==11){
                    
                    getResubmit();
                    if(signatureNow==1){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,1);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,1);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,1);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,1);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 2){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,2);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,2);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,2);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,2);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 3){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,3);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,3);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,3);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,3);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 4){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,4);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,4);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,4);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,4);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 5){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,5);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,5);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,5);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,5);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 6){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,6);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,6);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,6);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,6);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 7){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,7);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,7);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,7);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,7);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 8){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,8);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,8);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,8);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,8);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 9){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,9);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,9);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,9);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,9);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 10){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,10);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,10);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,10);//不能用变量，要么宏定义的常量可以
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,10);//不能用变量，要么宏定义的常量可以
                    }
                }else{
                    neighbor0=11;
                    neighbor1=0;
                    neighbor2=0;
                    neighbor3=0;
                    if(signatureNow==1){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,1);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 2){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,2);
                    }else if(signatureNow == 3){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,3);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 4){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,4);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 5){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,5);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 6){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,6);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 7){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,7);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 8){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,8);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 9){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,9);//不能用变量，要么宏定义的常量可以
                    }else if(signatureNow == 10){
                        GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,10);//不能用变量，要么宏定义的常量可以
                    }
                    
                }   
                    
            } else if(hdr.heartbeat.isValid()){
                if(hdr.heartbeat.heartbeat_type==ACK){
                    //reback the packets
                    heart_back.apply();
                    signatureNow =(reg_table_key_t) hdr.heartbeat.signature;
                     get_neighbor_id_and_state();
                    // STORE_MONITERED_ALIVE_REG_ACTION_X(x,n)  
                    if(hdr.heartbeat.signature==1){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,1);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,1);
                    }else if(hdr.heartbeat.signature == 2){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,2);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,2);
                    }else if(hdr.heartbeat.signature == 3){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,3);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,3);
                    }else if(hdr.heartbeat.signature == 4){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,4);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,4);
                    }else if(hdr.heartbeat.signature == 5){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,5);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,5);
                    }else if(hdr.heartbeat.signature == 6){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,6);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,6);
                    }else if(hdr.heartbeat.signature == 7){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,7);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,7);
                    }else if(hdr.heartbeat.signature == 8){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,8);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,8);
                    }else if(hdr.heartbeat.signature == 9){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,9);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,9);
                    }else if(hdr.heartbeat.signature == 10){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,10);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,10);
                    }else if(hdr.heartbeat.signature == 11){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,11);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,11);
                    }
                }          
            }
        }
        
        // No need for egress processing, skip it and use empty controls for egress.
        ig_intr_tm_md.bypass_egress = 1w1;
        // if(ig_intr_dprsr_md.digest_type ==1){
        //     if(meta.port_status.error_switch_0==9||meta.port_status.error_switch_1==9){
        //         down_time_count = down_time_id_reg_action.execute(9);
        //         store_down_time_reg_action.execute(down_time_count);
        //     }
        // }
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

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
