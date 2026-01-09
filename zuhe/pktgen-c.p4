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

parser SwitchIngressParser(
       packet_in packet, 
       out headers hdr, 
       out ingress_metadata_t meta,
       out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);

        pktgen_port_down_header_t pktgen_pd_hdr = packet.lookahead<pktgen_port_down_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            2 : parse_pktgen_timer;
            4: parse_pktgen_port_down;
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

    state parse_pktgen_timer {
        packet.extract(hdr.timer);
        transition meta_init;
    }
    state parse_pktgen_port_down {
        packet.extract(hdr.port_down);
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
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
           
    Digest<digest_t>() digest;
    apply {
        // Generate a digest, if digest_type is set in MAU.
        if (ig_intr_dprsr_md.digest_type == 1) {
            digest.pack({ig_md.signature,ig_md.port_0,ig_md.error_switch_0,ig_md.port_1,ig_md.error_switch_1});
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
        inout ingress_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    bit<32> neighbor_list;
    bit<48> ingress_global_time;
    bit<32> ingress_global_time_1;
    bit<32> ingress_global_time_2;
    bit<32> ingress_global_time_3;
    bit<1> heartbeat_type;
    bit<8> neighbor_f;
    bit<8> neighbor_l;
    register_state_t store_state;
    bit<1> ifTimeOut_f;
    bit<1> ifTimeOut_l;
    bit<3> neighbor_num;
    reg_remote_state_t reg_remote_state;
    bit<3> remote_next_port_state;
    neighbor_state_t statehf;
    neighbor_state_t statehl;

    PortId_t next_port;
    register_state_t next_port_state;
    reg_table_key_t reg_table_key;
    reg_key_half_t signature_Back = (reg_key_half_t) hdr.heartbeat.signature;
    reg_key_half_t Monitored_switch_Back = (reg_key_half_t) hdr.heartbeat.Monitored_switch;
    
    //the table of neighbor alive state
    Register<time_t, reg_table_key_t>(reg_table_size) neighbor_time_reg;
    RegisterAction<time_t, reg_table_key_t, bit<1>>(neighbor_time_reg) 
    store_neighbor_time_reg_action = {
        void apply(inout time_t value){
            value.time_1 = ingress_global_time_1;
            value.time_2 = ingress_global_time_2;
        }
    };
    RegisterAction<time_t, reg_table_key_t,bit<1>>(neighbor_time_reg)
    check_neighbor_time_reg_action = {
        void apply(inout time_t value, out bit<1> read_value){
            if(value.time_1 == (bit<32>)ingress_global_time_1){
                bit<32> ingress_global_time_dur = ingress_global_time_2-value.time_2;
                if(ingress_global_time_dur>time_duration_threshold){
                      read_value =1;
                }
            }
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

    //the table of neighbor alive state
    Register<bit<32>, reg_table_key_t>(node_num) neighbor_id_reg;
    RegisterAction<bit<32>, reg_table_key_t, bit<32>>(neighbor_id_reg) 
    read_neighbor_id_reg_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    //the table of neighbor alive state
    Register<reg_remote_state_t, reg_table_key_t>(node_num) remote_neighbor_alive_reg;
    RegisterAction<reg_remote_state_t, reg_table_key_t, reg_remote_state_t>(remote_neighbor_alive_reg) 
    read_remote_neighbor_alive_reg_action = {
        void apply(inout reg_remote_state_t value, out reg_remote_state_t read_value){
            read_value = value;
        }
    };
    RegisterAction<reg_remote_state_t, reg_table_key_t, reg_remote_state_t>(remote_neighbor_alive_reg) 
    store_remote_neighbor_alive_reg_action = {
        void apply(inout reg_remote_state_t value){
            value = reg_remote_state;
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



    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }
    action change_port(PortId_t back_port) {
        ig_intr_tm_md.ucast_egress_port = back_port;
    }
    action l3_switch(PortId_t port,PortId_t nextPortId) {
        ig_intr_tm_md.ucast_egress_port = port;
        next_port=nextPortId;
    }
    action getNeighborList( reg_table_key_t  Monitored_switch){
        neighbor_list = read_neighbor_id_reg_action.execute( Monitored_switch);
    }
    
    

    action add_heartbeat(signature_t signature,signature_t Monitored_switch){
          hdr.heartbeat.setValid();
          hdr.heartbeat.heartbeat_type = ACK;
          //hdr.heartbeat.protocol = hdr.ethernet.ether_type;
          hdr.heartbeat.signature = signature;
          hdr.ethernet.ether_type = ETHERTYPE_HEARTBEAT;
          hdr.heartbeat.Monitored_switch = Monitored_switch;
          hdr.heartbeat.state = 0;
    }

    action alive_register_action(){
        store_neighbor_alive_reg_action.execute(reg_table_key);
    }
    action heart_back_action() {
        hdr.heartbeat.setValid();    
        hdr.heartbeat.heartbeat_type = REPLY;
        ig_intr_tm_md.ucast_egress_port =  ig_intr_md.ingress_port;
    }
    action match(PortId_t port,signature_t signature,signature_t Monitored_switch) {
        ig_intr_tm_md.ucast_egress_port = port;
        // next_port=port;
        Monitored_switch_Back = (reg_key_half_t)Monitored_switch;
        signature_Back = (reg_key_half_t)signature;
        add_heartbeat(signature,Monitored_switch);
    }
    action match_down(PortId_t port,signature_t signature,signature_t Monitored_switch) {
        ig_intr_tm_md.ucast_egress_port = port;
        // next_port=port;
        Monitored_switch_Back = (reg_key_half_t)Monitored_switch;
        signature_Back = (reg_key_half_t)signature;
        add_heartbeat(signature,Monitored_switch);
        hdr.heartbeat.state = 1;
    }
   
    action carry_to_digest_0(){
        md.signature=(signature_t)hdr.heartbeat.signature;
        md.port_0=1;
        md.error_switch_0= (bit<7>)neighbor_f;
        ig_intr_dprsr_md.digest_type =1;
        // reset_neighbor_alive_reg_action.execute((bit<8>)neighbor_f);
    }
    action carry_to_digest_1(){
        md.port_1=1;
        md.error_switch_1= (bit<7>)neighbor_l;
        
        md.signature=(signature_t)hdr.heartbeat.signature;
        ig_intr_dprsr_md.digest_type =1;
        // reset_neighbor_alive_reg_action.execute((bit<8>)neighbor_l);
    }
    // action getTime(){
    //      }
   
    action getHeaderNeighborALL(){
        neighbor_f=(bit<8>)hdr.neighborState[0].neighbor;
        neighbor_l=(bit<8>)hdr.neighborState[1].neighbor;
        // neighbor_m=hdr.neighborState[2].neighbor;
        // neighbor_n=hdr.neighborState[3].neighbor;
    }
    action getHeaderNeighborALL_state(){
        statehf=hdr.neighborState[0].state;
        statehl=hdr.neighborState[1].state;
        // statehm=hdr.neighborState[2].state;
        // statehn=hdr.neighborState[3].state;
    }
    action neighbor_num_action(bit<3> neighborNum){
        neighbor_num = neighborNum;
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
    table neighbor_num_table{
        key = {
            next_port:exact;
        }
        actions={
            neighbor_num_action();
            NoAction;
        }
        size=node_num;
        default_action = NoAction();
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
        size = 1024;
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
        ingress_global_time= ig_intr_prsr_md.global_tstamp;
        ingress_global_time_1= (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
        ingress_global_time_2= ig_intr_prsr_md.global_tstamp[31:0];
    
        if (hdr.timer.isValid()) {
            timer_periodic.apply();
            reg_table_key =  (reg_table_key_t) hdr.heartbeat.Monitored_switch;
            store_neighbor_time_reg_action.execute(reg_table_key);
            store_state=0;
            alive_register_action();
        } else if (hdr.port_down.isValid()){
            port_down_table.apply();
            reg_table_key =  (reg_table_key_t) hdr.heartbeat.Monitored_switch;
            store_port_down_time_reg_action.execute(reg_table_key);
        }else if(hdr.heartbeat.isValid()){
            // heartbeat_type=hdr.heartbeat.heartbeat_type;
            if(hdr.heartbeat.heartbeat_type==ACK){
                heart_back.apply();
                reg_table_key =(reg_table_key_t)hdr.heartbeat.signature;
                store_state=1;
                alive_register_action();
                // hdr.heartbeat.signature == 11 || 
                if( hdr.heartbeat.signature == 12){
                    getHeaderNeighborALL();
                    // getHeaderNeighborALL_state();
                    statehf=hdr.neighborState[0].state;
                    statehl=hdr.neighborState[1].state;
                    reg_remote_state=(reg_remote_state_t)(statehl ++ statehf);
                    if(statehf==0){
                        carry_to_digest_0();
                    }
                    if(statehl==0){
                        carry_to_digest_1();
                    }   
                    store_remote_neighbor_alive_reg_action.execute(reg_table_key);
                }
            }else {
                reg_table_key = (reg_table_key_t)hdr.heartbeat.Monitored_switch;
                store_state=1;
                alive_register_action();
                drop();
            }
        }else{
            //normal forwarding
            forward_table.apply();
            ifTimeOut_f=check_neighbor_time_reg_action.execute( (bit<8>)neighbor_f);
                    
            reg_remote_state_t remote_state = read_remote_neighbor_alive_reg_action.execute(12);
            neighbor_num_table.apply();
            if (neighbor_num==0){
                remote_next_port_state = remote_state[2:0];
            }else if(neighbor_num==1){
                remote_next_port_state = remote_state[5:3];
            }
            next_port_state=read_neighbor_alive_reg_action.execute((bit<8>)next_port);
            if(next_port_state == NOALIVE){
                ig_intr_dprsr_md.digest_type = 1;
                change_port_table.apply();
            }
        }
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


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



