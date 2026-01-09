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
         meta.error_switch_0=0;
         meta.error_switch_1=0;
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
            // ,
            // ig_md.port_2,ig_md.error_switch_2,ig_md.port_3,ig_md.error_switch_3
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

    bit<32> neighbor_list;
    bit<48> ingress_global_time;
    bit<32> ingress_global_time_1;
    bit<32> ingress_global_time_2;
    bit<4> neighbor_f;
    bit<4> neighbor_l;
    bit<1> ifTimeOut_f;
    bit<1> ifTimeOut_l;
    bit<8> neighborf;
    bit<8> neighborl;
    bit<32> down_time_count;
    register_state_t store_state;
    neighbor_state_t statef;
    neighbor_state_t statel;
    neighbor_state_t stateM;
    neighbor_state_t stateM_2;
    reg_remote_state_t reg_remote_state;
    
    neighbor_state_t statehf;
    neighbor_state_t statehl;

    PortId_t next_port;
    register_state_t next_port_state;
    PortId_t replace_port;
    reg_table_key_t reg_table_key;
    reg_table_key_t signatureNow;
    reg_table_key_t Monitored_switch_now;
    reg_key_half_t signature_Back;

    //the batch of the packets
    Register<bit<1>, reg_table_key_t>(node_num) batch_time_reg;
    RegisterAction<bit<1>, reg_table_key_t, bit<1>>(batch_time_reg) 
    catch_batch_time_reg_action = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value=value;
            value=1;
        }
    };
    //remote
    Register<reg_remote_state_t, reg_table_key_t>(node_num) remote_neighbor_alive_reg;
    RegisterAction<reg_remote_state_t, reg_table_key_t, reg_remote_state_t>(remote_neighbor_alive_reg) 
    read_remote_neighbor_alive_reg_action = {
        void apply(inout reg_remote_state_t value, out reg_remote_state_t read_value){
            read_value = value;
        }
    };
    RegisterAction<reg_remote_state_t, reg_table_key_t, reg_remote_state_t>(remote_neighbor_alive_reg) 
    set_remote_neighbor_alive_reg_action = {
        void apply(inout reg_remote_state_t value,out reg_remote_state_t read_value){
            value = reg_remote_state;
        }
    };


    //the table of neighbor alive state
    Register<time_t, reg_table_key_t>(reg_table_size) remote_neighbor_time_reg;
    RegisterAction<time_t, reg_table_key_t, bit<1>>(remote_neighbor_time_reg) 
    store_remote_neighbor_time_reg_action = {
        void apply(inout time_t value){
            value.time_1 = (bit<32>)ingress_global_time[47:32];
            value.time_2 = ingress_global_time[31:0];
        }
    };
    //todo: check the time
    RegisterAction<time_t, reg_table_key_t,bit<1>>(remote_neighbor_time_reg)
    check_remote_neighbor_time_reg_action = {
        void apply(inout time_t value, out bit<1> read_value){
            if(value.time_1 == (bit<32>)ingress_global_time[47:32]){
                bit<32> ingress_global_time_dur = ingress_global_time[31:0]-value.time_2;
                if(ingress_global_time_dur>time_duration_threshold){
                      read_value =1;
                }
            }
        }
    };
        //the table of neighbor alive state
    Register<register_state_t, reg_table_key_t>(node_num) neighbor_alive_reg;
    RegisterAction<register_state_t, reg_table_key_t, register_state_t>(neighbor_alive_reg) 
    read_neighbor_alive_reg_action = {
        void apply(inout register_state_t value, out register_state_t read_value){
            read_value = value;
        }
    };

    RegisterAction<register_state_t, reg_table_key_t, register_state_t>(neighbor_alive_reg) 
    store_neighbor_alive_reg_action = {
        void apply(inout register_state_t value){
            value = store_state;
        }
    };

    //the table of neighbor alive state
    Register<time_t, reg_table_key_t>(reg_table_size) neighbor_time_reg;
    RegisterAction<time_t, reg_table_key_t, bit<1>>(neighbor_time_reg) 
    store_neighbor_time_reg_action = {
        void apply(inout time_t value){
            // if(stateM_2==1){ 
                value.time_1 = (bit<32>)ingress_global_time[47:32];
                value.time_2 = ingress_global_time[31:0];
            // }
        }
    };
    //todo: check the time
    RegisterAction<time_t, reg_table_key_t,bit<1>>(neighbor_time_reg)
    check_neighbor_time_reg_action = {
        void apply(inout time_t value, out bit<1> read_value){
            if(value.time_1 == (bit<32>)ingress_global_time[47:32]){
                bit<32> ingress_global_time_dur = ingress_global_time[31:0]-value.time_2;
                if(ingress_global_time_dur>time_duration_threshold){
                    // timeout
                      read_value =1;
                }else{
                    read_value=0;
                }
            }else{
                // timeout
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
    Register<bit<32>, reg_table_key_t>(65535) down_time_id_reg;
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
    Register<time_t, bit<32>>(reg_table_size) down_time_reg;
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
    action l3_switch(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_port=port;
    }
    
    action getNeighborList( reg_table_key_t  Monitored_switch){
        neighbor_list = read_neighbor_id_reg_action.execute( Monitored_switch);
    }
    action alive_register_action(){
        store_neighbor_alive_reg_action.execute(reg_table_key);
    }

    action setHeaderState_f(){
         hdr.neighborState[0].state=1;
    }
    action setHeaderState_l(){
         hdr.neighborState[1].state=1;
    }
    action heart_back_action() {
        hdr.heartbeat.setValid();    
        hdr.heartbeat.heartbeat_type = REPLY;
        hdr.heartbeat.state = 1;
        ig_intr_tm_md.ucast_egress_port =  ig_intr_md.ingress_port;
    }

    action getHeaderNeighborALL(){
        neighbor_f=hdr.neighborState[0].neighbor;
        neighbor_l=hdr.neighborState[1].neighbor;
    }
    action getHeaderNeighborALL_state(){
        statehf=hdr.neighborState[0].state;
        statehl=hdr.neighborState[1].state;
    }
  

    action add_heartbeat(signature_t signature,signature_t Monitored_switch){
        hdr.heartbeat.setValid();
        hdr.heartbeat.heartbeat_type = ACK;
        //hdr.heartbeat.protocol = hdr.ethernet.ether_type;
        hdr.heartbeat.signature = signature;
        hdr.ethernet.ether_type = ETHERTYPE_HEARTBEAT;
        hdr.heartbeat.Monitored_switch = Monitored_switch;
        neighbor_f=neighbor_list[3:0];
        neighbor_l=neighbor_list[7:4];
        hdr.neighborState[0].neighbor=neighbor_f;
        hdr.neighborState[1].neighbor=neighbor_l;
        // hdr.heartbeat.state = 0;
    }




    action match(PortId_t port,signature_t signature,signature_t Monitored_switch) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_port=port;
        signatureNow = (reg_table_key_t)signature;
        Monitored_switch_now=(reg_table_key_t)Monitored_switch;
        getNeighborList((reg_table_key_t)Monitored_switch);
        add_heartbeat(signature,Monitored_switch);
    }
    action match_consensus(PortId_t port,signature_t signature,signature_t Monitored_switch,bit<32> trans_neighbor_alive_list) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_port=port;
        signatureNow = (reg_table_key_t)signature;
        neighbor_list = trans_neighbor_alive_list;
        add_heartbeat(signature,Monitored_switch);
    }
    
    
    action carry_to_digest_0(){
        md.port_0=1;
        md.error_switch_0= (bit<7>)neighbor_f;
        ig_intr_dprsr_md.digest_type =1;
    }
    action carry_to_digest_1(){
        md.port_1=1;
        md.error_switch_1= (bit<7>)neighbor_l;
        ig_intr_dprsr_md.digest_type =1;
    }

    // action carry_to_digest_2(){
    //     md.port_2=1;
    //     md.error_switch_2= (bit<7>)neighbor_m;
    //     ig_intr_dprsr_md.digest_type =1;
    // }
    // action carry_to_digest_3(){
    //     md.port_3=1;
    //     md.error_switch_3= (bit<7>)neighbor_n;
    //     ig_intr_dprsr_md.digest_type =1;
    // }

    action init_header_state(){
        hdr.neighborState[0].state=1;
        hdr.neighborState[1].state=1;
        // hdr.neighborState[2].state=1;
        // hdr.neighborState[3].state=1;
    }
    action get_neighbor_id(){
        neighborf=(bit<8>)hdr.neighborState[0].neighbor;
        neighborl=(bit<8>)hdr.neighborState[1].neighbor;
        // neighborm=(bit<8>)hdr.neighborState[2].neighbor;
        // neighborn=(bit<8>)hdr.neighborState[3].neighbor;
    }
    action get_Monitored_switch(){
        reg_table_key =(reg_table_key_t)hdr.heartbeat.Monitored_switch;
    }
    action get_signature(){
        reg_table_key=(reg_table_key_t)hdr.heartbeat.signature;
    }

    action get_neighbor_alive_reg_action_f() {
       statef=(neighbor_state_t)read_neighbor_alive_reg_action.execute( (bit<8>)neighbor_f);
    }
    action get_neighbor_alive_reg_action_l() {
       statel=(neighbor_state_t)read_neighbor_alive_reg_action.execute( (bit<8>)neighbor_l);
    }
    action get_neighbor_alive_reg_action_M() {
       stateM=(neighbor_state_t)read_neighbor_alive_reg_action.execute( (bit<8>)hdr.heartbeat.Monitored_switch);
    }

    action read_next_port(){
        next_port_state=read_neighbor_alive_reg_action.execute((bit<8>)next_port);
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

    table heart_back {
        key = {
            hdr.heartbeat.heartbeat_type : exact;
            // hdr.heartbeat.Monitored_switch : exact;
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
    apply {
        //record the timestamp
        ingress_global_time= ig_intr_prsr_md.global_tstamp;
        ingress_global_time_1= (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
        ingress_global_time_2= ig_intr_prsr_md.global_tstamp[31:0];
        if (hdr.timer.isValid()) {
            //同时将心跳包发给对应的交换机
            timer_periodic.apply();\
            bit<8> key = (bit<8>)hdr.heartbeat.Monitored_switch;
            //第一组数据包不读状态？
            bit<1> batch_time = catch_batch_time_reg_action.execute((bit<8>)hdr.heartbeat.Monitored_switch);
            if(batch_time==0){
                init_header_state();
                stateM_2=1;
                @stage(5){store_neighbor_time_reg_action.execute(key);}
            }else if (batch_time==1){
                //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机
                md.signature=(signature_t)signatureNow;
                
                reg_table_key_t key=(reg_table_key_t)signatureNow;
                store_state=0;
                @stage(3){
                    get_neighbor_alive_reg_action_f();
                    get_neighbor_alive_reg_action_l();
                    get_neighbor_alive_reg_action_M();
                    alive_register_action();
                }
                
                stateM_2=stateM;
                @stage(5){
                    ifTimeOut_f=check_neighbor_time_reg_action.execute( (bit<8>)neighbor_f);
                    ifTimeOut_l=check_neighbor_time_reg_action.execute( (bit<8>)neighbor_l);
                    if(stateM_2==1){
                        store_neighbor_time_reg_action.execute(key);
                    }
                }
                neighbor_state_t statef_2=statef;
                if(neighbor_f!=0){
                    if(ifTimeOut_f==1 && statef_2==0){
                        carry_to_digest_0();     
                    }else{
                        setHeaderState_f();
                    }
                }
                neighbor_state_t statel_2=statel;
                if(neighbor_l!=0){
                    if(ifTimeOut_l==1&&statel_2==0){
                        carry_to_digest_1();
                    }else{
                        setHeaderState_l();
                    }
                } 
                
            }
        } else if(hdr.heartbeat.isValid()){  
            
             if(hdr.heartbeat.heartbeat_type==ACK){
                heart_back.apply();
                reg_table_key =(reg_table_key_t) hdr.heartbeat.signature;
                 @stage(3){
                    store_state=1;
                    alive_register_action();
                    }
                // alive_register_action();
             }else{
                reg_table_key = (bit<8>) hdr.heartbeat.Monitored_switch;
                @stage(3){
                    store_state=1;
                    alive_register_action();
                }
                drop();
             }
        }else{
            //normal forwarding
            forward_table.apply();
            read_next_port();
            bit<8> key1=(bit<8>)next_port;
            @stage(5){
                ifTimeOut_l=check_neighbor_time_reg_action.execute(key1 );
            }
            set_remote_neighbor_alive_reg_action.execute(12);
            if(ifTimeOut_l==1 && next_port_state == NOALIVE){
                ig_intr_dprsr_md.digest_type = 1;
                change_port_table.apply();
                // replace_port = (PortId_t)read_next_port_reg_action.execute((reg_table_key_t)next_port);
                // ig_intr_tm_md.ucast_egress_port = replace_port;
            }
        }
        // No need for egress processing, skip it and use empty controls for egress.
        ig_intr_tm_md.bypass_egress = 1w1;
        if(ig_intr_dprsr_md.digest_type ==1){
            down_time_count = down_time_id_reg_action.execute(0);
            store_down_time_reg_action.execute(down_time_count);
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
