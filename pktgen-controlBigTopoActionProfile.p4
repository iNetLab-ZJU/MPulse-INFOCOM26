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
            4 : parse_pktgen_port_down;
            default : parse_ethernet;
        }
    }
    state  meta_init{
         meta.port_0=0;
         meta.port_1=0;
         meta.port_2=0;
         meta.port_3=0;
         meta.error_switch_0=0;
         meta.error_switch_1=0;
         meta.error_switch_2=0;
         meta.error_switch_3=0;
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
            digest.pack({ig_md.signature,ig_md.port_0,ig_md.error_switch_0,ig_md.port_1,ig_md.error_switch_1
            ,
            ig_md.port_2,ig_md.error_switch_2,ig_md.port_3,ig_md.error_switch_3
            });
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
        inout  ingress_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    Hash<bit<16>>(HashAlgorithm_t.CRC16) sig1_hash;
    ActionProfile(2048) catch_action_selector_ap;
    ActionSelector(action_profile = catch_action_selector_ap, // action profile
                   hash = sig1_hash, // hash extern
                   mode = SelectorMode_t.FAIR, // Selector algorithm
                   max_group_size = 200, // max group size
                   num_groups = 100 // max number of groups
                   ) catch_action_selector;

    bit<32> neighbor_list=0;
    bit<48> ingress_global_time=0;
    bit<4> neighbor_num=4;
    bit<4> neighbor_0=0;
    bit<4> neighbor_1=0;
    bit<4> neighbor_2=0;
    bit<4> neighbor_3=0;
    bit<1> ifTimeOut_0=0;
    bit<1> ifTimeOut_1=0;
    bit<1> ifTimeOut_2=0;
    bit<1> ifTimeOut_3=0;
    bit<8> neighbor0=0;
    bit<8> neighbor1=0;
    bit<8> neighbor2=0;
    bit<8> neighbor3=0;
    bit<32> down_time_count=0;
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
    register_state_t stateM=0;
    // register_state_t stateM_2=0;
    reg_remote_state_t reg_remote_state=0;
    
    neighbor_state_t stateh0=0;
    neighbor_state_t stateh1=0;
    neighbor_state_t stateh2=0;
    neighbor_state_t stateh3=0;

    PortId_t next_Switch=0;
    register_state_t next_Switch_state=0;
    register_state_t next_switch_stateAll=0;
    bit<1> timeout_next_Switch=0;

    PortId_t next_port=0;
    register_state_t next_port_state=0;
    register_state_t next_port_stateAll=0;
    bit<1> timeout_next_port=0;

    PortId_t replace_port=0;
    reg_table_key_t reg_table_key=0;
    reg_table_key_t signatureNow=0;
    // reg_table_key_t Monitored_=0switch_now;
    reg_key_half_t signature_Back=0;

    //the batch of the packets,the first batch to init the packets
    Register<bit<1>, reg_table_key_t>(node_num) batch_time_reg;
    RegisterAction<bit<1>, reg_table_key_t, bit<1>>(batch_time_reg) 
    catch_batch_time_reg_action = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value=value;
            value=1;
        }
    };
    //remote
    // Register<reg_remote_state_t, reg_table_key_t>(node_num) remote_neighbor_alive_reg;
    // RegisterAction<reg_remote_state_t, reg_table_key_t, reg_remote_state_t>(remote_neighbor_alive_reg) 
    // read_remote_neighbor_alive_reg_action = {
    //     void apply(inout reg_remote_state_t value, out reg_remote_state_t read_value){
    //         read_value = value;
    //     }
    // };
    // RegisterAction<reg_remote_state_t, reg_table_key_t, reg_remote_state_t>(remote_neighbor_alive_reg) 
    // set_remote_neighbor_alive_reg_action = {
    //     void apply(inout reg_remote_state_t value,out reg_remote_state_t read_value){
    //         value = reg_remote_state;
    //     }
    // };


 
    //the table of neighbor alive state (key-states)
    Register<reg_table_key_t, reg_table_key_t>(node_num) neighbor_alive_reg;
    RegisterAction<reg_table_key_t, reg_table_key_t, reg_table_key_t>(neighbor_alive_reg) 
    read_neighbor_alive_reg_action = {
        void apply(inout reg_table_key_t value, out reg_table_key_t read_value){
            read_value = value;
        }
    };

    RegisterAction<reg_table_key_t, reg_table_key_t, reg_table_key_t>(neighbor_alive_reg) 
    store_neighbor_alive_reg_action = {
        void apply(inout reg_table_key_t value){
            value = NOALIVE;
        }
    };

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
            value = store_state;\
        }\
    };
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
    Register<bit<32>, reg_table_key_t>(node_num) next_port_reg;
    RegisterAction<bit<32>, reg_table_key_t, bit<32>>(next_port_reg) 
    read_next_port_reg_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };
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
    action alive_register_action(){
        store_neighbor_alive_reg_action.execute(reg_table_key);
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

    action getHeaderNeighborALL(){
        neighbor_0=hdr.neighborState[0].neighbor;
        neighbor_1=hdr.neighborState[1].neighbor;
        neighbor_2=hdr.neighborState[2].neighbor;
        neighbor_3=hdr.neighborState[3].neighbor;
    }

    // action getHeaderNeighborALL_state(){
    //     stateh0=hdr.neighborState[0].state;
    //     stateh1=hdr.neighborState[1].state;
    //     stateh2=hdr.neighborState[2].state;
    //     stateh3=hdr.neighborState[3].state;
    // }
    // action get_neighbor_id_totalLength(){
    //     neighbor0=(bit<8>)neighbor_0;
    //     neighbor1=(bit<8>)neighbor_1;
    //     neighbor2=(bit<8>)neighbor_2;
    //     neighbor3=(bit<8>)neighbor_3;
    // }

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
    
    
    action carry_to_digest_0(){
        md.port_0=1;
        md.error_switch_0= (bit<7>)neighbor_0;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_1(){
        md.port_1=1;
        md.error_switch_1= (bit<7>)neighbor_1;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_2(){
        md.port_2=1;
        md.error_switch_2= (bit<7>)neighbor_2;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_3(){
        md.port_3=1;
        md.error_switch_3= (bit<7>)neighbor_3;
        ig_intr_dprsr_md.digest_type =1;
    }


    action init_header_state(){
        hdr.neighborState[0].state=1;
        hdr.neighborState[1].state=1;
        hdr.neighborState[2].state=1;
        hdr.neighborState[3].state=1;
    }
    action get_neighbor_id_and_state(){
        neighbor0=(bit<8>)hdr.neighborState[0].neighbor;
        neighbor1=(bit<8>)hdr.neighborState[1].neighbor;
        neighbor2=(bit<8>)hdr.neighborState[2].neighbor;
        neighbor3=(bit<8>)hdr.neighborState[3].neighbor;
        state0=(register_state_t)hdr.neighborState[0].state;
        state1=(register_state_t)hdr.neighborState[1].state;
        state2=(register_state_t)hdr.neighborState[2].state;
        state3=(register_state_t)hdr.neighborState[3].state;
    }
    

#define STORE_MONITERED_ALIVE_REG_ACTION_X(x,n)\
        if (neighbor_##x##!=0){     \
        @stage(5)\
        {\
            store_state=state##x##;\
            store_neighbor_alive_reg_##n##_action.execute(neighbor##x##);\
            store_neighbor_time_##n##_reg_action.execute(neighbor##x##);\
            if(store_state==0){  \
                carry_to_digest_##x##();       \
            }\
        }       \ 
        }
// reg_table_key_t neighbor=(reg_table_key_t)neighbor_##x##;    
#define STORE_MONITERED_ALIVE_REG_ACTION(n)\
            @stage(5)\
            {\
                store_neighbor_alive_reg_##n##_action.execute(reg_table_key);\
                store_neighbor_time_##n##_reg_action.execute(reg_table_key);\
            }
    // bit<32> neighborList;            
    // neighborList = read_neighbor_id_reg_action.execute( neighbor_##x##);
    // bit<4> neighbor_1=neighborList[3:0];
    // bit<4> neighbor_2=neighborList[7:4];
    // bit<4> neighbor_3=neighborList[11:8];
    // bit<4> neighbor_4=neighborList[15:12]; 
#define GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(x,n)      \
        if (neighbor_##x##!=0){     \
            @stage(5){\
                state##x## =read_neighbor_alive_reg_##n##_action.execute((reg_table_key_t)neighbor_##x##);\
                timeout_##x##=check_neighbor_time_##n##_reg_action.execute((reg_table_key_t) neighbor_##x##);\
            }\
            if(timeout_##x##==1 && state##x##==0){  \
                carry_to_digest_##x##();       \
            }else{  \
                setHeaderState_##x##();   \
            }   \
        }

// #define GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(x,n)      \
//         if (neighbor_##x##!=0){     \
//             @stage(5){\
//                 state##x## =read_neighbor_alive_reg_##n##_action.execute((reg_table_key_t)neighbor##x##);\
//                 timeout_##x##=check_neighbor_time_##n##_reg_action.execute((reg_table_key_t) neighbor##x##);\
//             }\
//             if(timeout_##x##==1 && state##x##==0){  \
//                 carry_to_digest_##x##();       \
//             }else{  \
//                 setHeaderState_##x##();   \
//             }   \
//         }
//     action get_neighbor_state(reg_table_key_t signatureNow,reg_table_key_t  Monitored_switch){
//         GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,0)
//     }
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
    // table getState_table{
    //     key = {
    //         signatureNow: exact; 
    //         Monitored_switch: exact;
    //     }
    //     actions = {
    //         get_neighbor_state;
    //         NoAction;
    //     }
    //     size=1024;
    //     implementation=catch_action_selector;
    // }
    
    apply {
        //record the timestamp
        ingress_global_time= ig_intr_prsr_md.global_tstamp;
        //if is timer packets
        if (hdr.timer.isValid()) {
            //同时将心跳包发给对应的交换机 init the intial information
            timer_periodic.apply();
            //被监测的交换机
            reg_table_key = (bit<8>)hdr.heartbeat.Monitored_switch;
            //第一组数据包不读状态？
            bit<1> batch_time = catch_batch_time_reg_action.execute((bit<8>)hdr.heartbeat.Monitored_switch);
            if(batch_time==0){
                //初始各个邻居状态为1
                init_header_state();
                // stateM_2=1;
                // @stage(4){store_neighbor_time_reg_action.execute(reg_table_key);}
                //在本地检测寄存器中初始存储被检测节点的时间
                store_neighbor_time_11_reg_action.execute(reg_table_key);
            }else if (batch_time==1){
                //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机
                md.signature=(signature_t)signatureNow;                
                state0=0;
                state1=0;
                state2=0;
                state3=0;
                //store the monitered switch's state
                // store_neighbor_alive_reg_action.execute(reg_table_key);
                // store_neighbor_time_reg_action.execute(reg_table_key);
                //get the monitered switch's neighbors state
                if(signatureNow==11){
                        STORE_MONITERED_ALIVE_REG_ACTION(11);
                    GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(0,11);
                    GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(1,11);
                    GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(2,11);
                    GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(3,11);
                }
            }
        } else if(hdr.heartbeat.isValid()){
            if(hdr.heartbeat.state==1){
                neighbor_1 = (bit<4>) hdr.heartbeat.signature;
                carry_to_digest_1();
                drop();
            }else {
                if(hdr.heartbeat.heartbeat_type==ACK){
                    //reback the packets
                    heart_back.apply();
                    reg_table_key =(reg_table_key_t) hdr.heartbeat.signature;
                    get_neighbor_id_and_state();
                    // STORE_MONITERED_ALIVE_REG_ACTION_X(x,n)  
                    if(signatureNow==1){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,1);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,1);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,1);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,1);
                    }else if(signatureNow == 2){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,2);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,2);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,2);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,2);
                    }else if(signatureNow == 3){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,3);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,3);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,3);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,3);
                    }else if(signatureNow == 4){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,4);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,4);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,4);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,4);
                    }else if(signatureNow == 5){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,5);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,5);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,5);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,5);
                    }else if(signatureNow == 6){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,6);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,6);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,6);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,6);
                    }else if(signatureNow == 7){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,7);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,7);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,7);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,7);
                    }else if(signatureNow == 8){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,8);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,8);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,8);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,8);
                    }else if(signatureNow == 9){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,9);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,9);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,9);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,9);
                    }else if(signatureNow == 10){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,10);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,10);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,10);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,10);
                    }else if(signatureNow == 11){
                            STORE_MONITERED_ALIVE_REG_ACTION_X(0,11);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(1,11);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(2,11);
                            STORE_MONITERED_ALIVE_REG_ACTION_X(3,11);
                    }
                    // alive_register_action();
                }else{
                    //get the reback packets
                    reg_table_key = (bit<8>) hdr.heartbeat.Monitored_switch;
                    drop();
                }
                get_neighbor_id_and_state();
                store_state=1;
                store_neighbor_alive_reg_11_action.execute(reg_table_key);
                // store_time(neighbor_1,)
                //  @stage(3){
                //      if(reg_table_key==1){store_neighbor_alive_reg_1_action.execute(0);}
                // else if(reg_table_key==2){store_neighbor_alive_reg_2_action.execute(0);}
                // else if(reg_table_key==3){store_neighbor_alive_reg_3_action.execute(0);}
                // else if(reg_table_key==4){store_neighbor_alive_reg_4_action.execute(0);}
                // else if(reg_table_key==5){store_neighbor_alive_reg_5_action.execute(0);}
                // else if(reg_table_key==6){store_neighbor_alive_reg_6_action.execute(0);}
                // else if(reg_table_key==7){store_neighbor_alive_reg_7_action.execute(0);}
                // else if(reg_table_key==8){store_neighbor_alive_reg_8_action.execute(0);}
                // else if(reg_table_key==9){store_neighbor_alive_reg_9_action.execute(0);} 
                // else if(reg_table_key==10){store_neighbor_alive_reg_10_action.execute(0);}
                // else if(reg_table_key==11){store_neighbor_alive_reg_11_action.execute(0);}
                //  }
            }
        }else{
            //normal forwarding
            forward_table.apply();
        //    @stage(3){ 
        //     read_next_port();
        //     }
            bit<8> key1=(bit<8>)next_Switch;
            next_Switch_state =read_neighbor_alive_reg_11_action.execute(key1);
            timeout_next_Switch =check_neighbor_time_11_reg_action.execute(key1);
            if(timeout_next_Switch==1 && next_Switch_state==0){  
                change_port_table.apply();
            } 

    // #define GET_SELF_NEIGHBOR_ALIVE_REG_ACTION(x,n)      \
    //     if (neighbor_##x##!=0){     \
    //         @stage(5){\
    //             state##x## =read_neighbor_alive_reg_##n##_action.execute((reg_table_key_t)neighbor##x##);\
    //             timeout_##x##=check_neighbor_time_##n##_reg_action.execute((reg_table_key_t) neighbor##x##);\
    //         }\
    //         if(timeout_##x##==1 && state##x##==0){  \
    //             carry_to_digest_##x##();       \
    //         }else{  \
    //             setHeaderState_##x##();   \
    //         }   \
    //     }
// getNeighborList( reg_table_key_t  Monitored_switch)
            //检测器检测到的结果
            // next_Switch_state = next_Switch_state_action.execute(key1);
            // @stage(5){
            //     // ifTimeOut_l=check_neighbor_time_reg_action.execute(key1 );
            //          if (key1==1){ifTimeOut_l=check_neighbor_time_1_reg_action.execute(key1 );}
            //     else if (key1==2){ifTimeOut_l=check_neighbor_time_2_reg_action.execute(key1 );}
            //     else if (key1==3){ifTimeOut_l=check_neighbor_time_3_reg_action.execute(key1 );}
            //     else if (key1==4){ifTimeOut_l=check_neighbor_time_4_reg_action.execute(key1 );}
            //     else if (key1==5){ifTimeOut_l=check_neighbor_time_5_reg_action.execute(key1 );}
            //     else if (key1==6){ifTimeOut_l=check_neighbor_time_6_reg_action.execute(key1 );}
            //     else if (key1==7){ifTimeOut_l=check_neighbor_time_7_reg_action.execute(key1 );}
            //     else if (key1==8){ifTimeOut_l=check_neighbor_time_8_reg_action.execute(key1 );}
            //     else if (key1==9){ifTimeOut_l=check_neighbor_time_9_reg_action.execute(key1 );}
            //     else if (key1==10){ifTimeOut_l=check_neighbor_time_10_reg_action.execute(key1 );}
            // }
            // set_remote_neighbor_alive_reg_action.execute(12);
            // if(ifTimeOut_l==1 && next_port_state == NOALIVE){
            //     ig_intr_dprsr_md.digest_type = 1;
            //     change_port_table.apply();
            //     // replace_port = (PortId_t)read_next_port_reg_action.execute((reg_table_key_t)next_port);
            //     // ig_intr_tm_md.ucast_egress_port = replace_port;
            // }
        }
        // No need for egress processing, skip it and use empty controls for egress.
        // ig_intr_tm_md.bypass_egress = 1w1;
        // if(ig_intr_dprsr_md.digest_type ==1){
        //     if(md.error_switch_0==9||md.error_switch_1==9){
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
