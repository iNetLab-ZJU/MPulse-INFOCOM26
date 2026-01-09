#include "common/API.p4"
control SwitchIngress_11
(
            inout headers hdr, 
            inout  ingress_metadata_t meta,
            in ingress_intrinsic_metadata_t ig_intr_md,
            in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
            inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
            inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        
        GET_MASK_CONTROL() get_mask_control;
        state_string_t maskNow;
        state_string_t maskNow1=0;
        MODIFY_REGISTER_STATE() register_state_1;
        MODIFY_REGISTER_STATE() register_state_2;
        MODIFY_REGISTER_STATE() register_state_5;
        MODIFY_REGISTER_STATE() register_state_6;


        MODIFY_REGISTER_TIME()  register_time_1;
        MODIFY_REGISTER_TIME()  register_time_2;
        MODIFY_REGISTER_TIME()  register_time_5;
        MODIFY_REGISTER_TIME()  register_time_6;

        bit<32> neighbor_list=0;
        reg_table_key_t next_switch_reg_key;
        reg_table_key_t next_switch_reg_key_1;
        bit<48> ingress_global_time=ig_intr_prsr_md.global_tstamp;
        bit<32> ingress_global_time_1;
        bit<32> ingress_global_time_2;
        bit<32> ingress_global_time_2_back_1 ;
        bit<32> ingress_global_time_2_back_2 ;
        bit<32> ingress_global_time_2_back_3 ;
        bit<32> ingress_global_time_2_back_4 ;
        state_string_t read_pad_state_ack_1;
        state_string_t read_pad_state_5;
        state_string_t read_pad_state_6;
        state_string_t read_pad_state_1;
        state_string_t read_pad_state_2;
        state_string_t read_pad_state_9;
        state_string_t read_pad_state_10;
        bit<1> read_pad_time_1;
        bit<1> read_pad_time_2;
        bit<1> read_pad_time_5;
        bit<1> read_pad_time_6;
        bit<1> read_pad_time_9;
        bit<1> read_pad_time_10;
        bit<1> read_pad_time_11;
        bit<1> read_pad_time_21;
        bit<1> read_pad_time_51;
        bit<1> read_pad_time_61;
        bit<1> read_pad_time_91;
        bit<1> read_pad_time_101;

        

        state_string_t read_pad_state_reback_1;
        state_string_t read_pad_state_reback_2;
        state_string_t read_pad_state_reback_5;
        state_string_t read_pad_state_reback_6;
        bit<1> read_pad_time_reback_1;
        bit<1> read_pad_time_reback_2;
        bit<1> read_pad_time_reback_5;
        bit<1> read_pad_time_reback_6;

        bit<1> read_pad_time_reback_11;
        bit<1> read_pad_time_reback_21;
        bit<1> read_pad_time_reback_51;
        bit<1> read_pad_time_reback_61;
        state_string_t state_all;
        state_string_t stateInput;
        bit<4> neighbor_num=4;
        bit<4> neighbor_0;
        bit<4> neighbor_1;
        bit<4> neighbor_2;
        bit<4> neighbor_3;
        reg_table_key_t neighbor0=0;
        reg_table_key_t neighbor1=0;
        reg_table_key_t neighbor2=0;
        reg_table_key_t neighbor3=0;
        bit<32> down_time_count=0;
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
        state_string_t state_all_0=0;
        state_string_t state_all_1=0;
        state_string_t state_all_2=0;
        state_string_t state_all_3=0;
        state_string_t state_all_4=0;
        state_string_t state_all_5=0;
        state_string_t state_all_6=0;
        state_string_t state_all_9=0;
        state_string_t state_all_10=0;
        state_string_t state_all_11=0;
        state_string_t state_all0=0;
        state_string_t state_all1=0;
        state_string_t state_all2=0;
        state_string_t state_all5=0;
        state_string_t state_all6=0;
        state_string_t state_all9=0;
        state_string_t state_all10=0;
        
        register_state_t store_state_0=0;
        register_state_t store_state_1=0;
        register_state_t store_state_2=0;
        register_state_t store_state_3=0;
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
        register_state_t next_Switch_state0=0;
        register_state_t next_Switch_state1=0;
        register_state_t next_Switch_state2=0;
        register_state_t next_Switch_state3=0;
        register_state_t next_switch_state_all;

        bit<1> timeout_next_Switch=0;
        bit<1> timeout_next_Switch0=0;
        bit<1> timeout_next_Switch1=0;
        bit<1> timeout_next_Switch2=0;
        bit<1> timeout_next_Switch3=0;
        bit<1> timeout_next_Switch4=0;
        bit<1> timeout_next_Switch5=0;
        bit<1> timeout_next_Switch6=0;
        bit<1> timeout_next_Switch9=0;
        bit<1> timeout_next_Switch10=0;
        bit<1> timeout_next_Switch11=0;

        bit<1> timeout_forward_Switch0=0;
        bit<1> timeout_forward_Switch1=0;
        bit<1> timeout_forward_Switch2=0;

        bit<1> timeout_forward_Switch3=0;

        state_string_t read_pad_state0=0;
        state_string_t read_pad_state1=0;
        state_string_t read_pad_state2=0;
        state_string_t read_pad_state5=0;
        state_string_t read_pad_state6=0;
        state_string_t read_pad_state9=0;
        state_string_t read_pad_state10=0;
                bit<1> read_pad_time_out_Switch=0;
                bit<1> read_pad_time_out_Switch1=0;
                bit<1> read_pad_time_out_Switch2=0;
                bit<1> read_pad_time_out_Switch3=0;
                bit<1> read_pad_time_out_Switch4=0;
                bit<1> read_pad_time_out_Switch5=0;
                bit<1> read_pad_time_out_Switch6=0;
                bit<1> read_pad_time_out_Switch9=0;
                bit<1> read_pad_time_out_Switch10=0;
                bit<1> read_pad_time_out_Switch11=0;   

        PortId_t next_port=0;
        register_state_t next_port_state=0;
        register_state_t next_port_stateAll=0;
        bit<1> timeout_next_port=0;

        PortId_t replace_port=0;
        reg_table_key_t reg_table_key=0;
        reg_table_key_t reg_table_key_monitered=0;
        reg_table_key_t reg_table_key_monitered2=0;
        reg_table_key_t signatureNow=0;
        reg_table_key_t signatureNow2=0;
        // reg_table_key_t Monitored_=0switch_now;
        reg_key_half_t signature_Back=0;
        reg_table_key_t Monitored_switch_now=0;

        // Register<time_t, reg_table_key_t>(reg_table_size) port_down_time_reg;
        // RegisterAction<time_t, reg_table_key_t, bit<1>>(port_down_time_reg) 
        // store_port_down_time_reg_action = {
        //     void apply(inout time_t value){
        //         value.time_1 = (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
        //         value.time_2 = ig_intr_prsr_md.global_tstamp[31:0];
        //     }
        // };
        // RegisterAction<time_t, reg_table_key_t,bit<1>>(port_down_time_reg)
        // check_port_down_time_reg_action = {
        //     void apply(inout time_t value, out bit<1> read_value){
        //         if(value.time_1 == (bit<32>)ig_intr_prsr_md.global_tstamp[47:32]){
        //             bit<32> ingress_global_time_dur = ig_intr_prsr_md.global_tstamp[31:0]-value.time_2;
        //             if(ingress_global_time_dur>time_duration_threshold){
        //                 read_value =1;
        //             }
        //         }
        //     }
        // };
        //the table of neighbor id
        Register<bit<32>, reg_table_key_t>(node_num) neighbor_id_reg;
        RegisterAction<bit<32>, reg_table_key_t, bit<32>>(neighbor_id_reg) 
        read_neighbor_id_reg_action = {
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
                value.time_1 = (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
                value.time_2 = ig_intr_prsr_md.global_tstamp[31:0];
            }
        };
        #include "Ingress_register_control.p4"
                
        action getNeighborList( reg_table_key_t  Monitored_switch){
            neighbor_list = read_neighbor_id_reg_action.execute( Monitored_switch);
        }

        action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1;
        }

        action change_port(PortId_t back_port) {
            ig_intr_tm_md.ucast_egress_port = back_port;
        }
        action getNeighbors(){
            neighbor_0=neighbor_list[3:0];
            neighbor_1=neighbor_list[7:4];
            neighbor_2=neighbor_list[11:8];
            neighbor_3=neighbor_list[15:12];

        }
        action l3_switch(PortId_t port,PortId_t nextSwitchId) {
            ig_intr_tm_md.ucast_egress_port = port;
            next_switch_reg_key=(reg_table_key_t)nextSwitchId;
            next_switch_reg_key_1=(reg_table_key_t)nextSwitchId;
            getNeighborList((reg_table_key_t)next_switch_reg_key_1);
            getNeighbors();
        }
        


        action heart_back_action() {
            // hdr.heartbeat.setValid(); 
            // get_neighbor_id_and_state();   
            hdr.heartbeat.heartbeat_type = REPLY;
            ig_intr_tm_md.ucast_egress_port =  ig_intr_md.ingress_port;
            neighbor_0 = hdr.neighborState[0].neighbor;
            neighbor_1 = hdr.neighborState[1].neighbor;
            neighbor_2 = hdr.neighborState[2].neighbor;
            neighbor_3 = hdr.neighborState[3].neighbor;

            signatureNow=(reg_table_key_t) hdr.heartbeat.signature; 
            signatureNow2=(reg_table_key_t) hdr.heartbeat.signature;
            store_state_0 = (register_state_t)hdr.neighborState[0].state;
            store_state_1 = (register_state_t)hdr.neighborState[1].state;
            store_state_2 = (register_state_t)hdr.neighborState[2].state;
            store_state_3 = (register_state_t)hdr.neighborState[3].state;
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
            meta.signature=signature;  
            signatureNow = (reg_table_key_t)signature;
            signatureNow2=(reg_table_key_t)signature;    
            // Monitored_switch_now=(reg_table_key_t)Monitored_switch;
            // 对方的邻居节点
            getNeighborList((reg_table_key_t)Monitored_switch);
            add_heartbeat(signature,Monitored_switch);
            reg_table_key_monitered = (reg_table_key_t)Monitored_switch; 
        }
        // action match_consensus(PortId_t port,signature_t signature,signature_t Monitored_switch,bit<32> trans_neighbor_alive_list) {
        //     ig_intr_tm_md.ucast_egress_port = port;
        //     signatureNow = (reg_table_key_t)signature;
        //     neighbor_list = trans_neighbor_alive_list;
        //     add_heartbeat(signature,Monitored_switch);
        // }
        action match_down(PortId_t port,signature_t signature,signature_t Monitored_switch) {
            ig_intr_tm_md.ucast_egress_port = port;
            // next_port=port;
            // Monitored_switch_Back = (reg_key_half_t)Monitored_switch;
            signature_Back = (reg_key_half_t)signature;
            add_heartbeat(signature,Monitored_switch);
            hdr.heartbeat.state = 1;
        }
        action get_time(){
            ingress_global_time_2 = ig_intr_prsr_md.global_tstamp[31:0]; 
            ingress_global_time_2_back_1 = ig_intr_prsr_md.global_tstamp[31:0]; 
            ingress_global_time_2_back_2 = ig_intr_prsr_md.global_tstamp[31:0]; 
            ingress_global_time_2_back_3 = ig_intr_prsr_md.global_tstamp[31:0]; 
            ingress_global_time_2_back_4 = ig_intr_prsr_md.global_tstamp[31:0]; 
        }

            
            #define return_register_state(n)\
                action return_register_state_##n() {\
                    state_all=state_all##n##;\
                    stateInput=state_all##n##;\
                }
            return_register_state(1)
            return_register_state(2)
            return_register_state(5)
            return_register_state(6)
            return_register_state(9)
            return_register_state(10)
                
            
            table tbl_get_value_state {
                key = {
                    next_switch_reg_key : exact;
                }
                actions = {
                    return_register_state_1;
                    return_register_state_2;
                    return_register_state_5;
                    return_register_state_6;
                    return_register_state_9;
                    return_register_state_10;
                }
                const entries = {
                    1:  return_register_state_1;
                    2:  return_register_state_2;
                    5:  return_register_state_5;
                    6:  return_register_state_6;
                    9:  return_register_state_9;
                    10: return_register_state_10;
                }
                size = 16;
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
                    // match_consensus;
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
                    // flow_id:exact;
                    next_switch_state_all:exact;
                    timeout_forward_Switch0:exact;
                    timeout_forward_Switch1:exact;
                    next_switch_reg_key_1:  exact;
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
            get_time();
            // No need for egress processing, skip it and use empty controls for egress.
            ig_intr_tm_md.bypass_egress = 1w1;
                //record the timestamp
        // if(ig_intr_md.resubmit_flag==0){
                    //This is the first pass of the ingress pipeline for this packet.
                    //if is timer packets
            if (hdr.timer.isValid()) {
                //同时将心跳包发给对应的交换机 init the intial information
                timer_periodic.apply();
                //被监测的交换机
                
                //第一组数据包不读状态？
                // bit<1> batch_time = catch_batch_time_reg_action.execute((reg_table_key_t)hdr.heartbeat.Monitored_switch);
                // if (batch_time==1){
                    //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机         
                    //store the monitered switch's state
                    // get_mask.apply(hdr,meta,signatureNow,mask_5,mask_6       ); 

                 
                    // if(signatureNow==1|| signatureNow==2){
                           
                        if(signatureNow2==1){
                             register_state_1.apply(1,0b0000100000000000,0,state_all);
                             register_time_1.apply(1,11,ingress_global_time_2,timeout_next_Switch1);
                         register_state_5.apply(0,0,0,state_all_0);
                        register_time_5.apply(0,11,ingress_global_time_2,timeout_0);
                    
                        register_state_6.apply(0,0,0,state_all_1);
                        register_time_6.apply(0,11,ingress_global_time_2,timeout_1);
                        }else if (signatureNow2==2){
                            register_state_2.apply(1,0b0000100000000000,0,state_all);
                            register_time_2.apply(1,11,ingress_global_time_2,timeout_next_Switch2);
                         register_state_5.apply(0,0,0,state_all_0);
                        register_time_5.apply(0,11,ingress_global_time_2,timeout_0);
                    
                        register_state_6.apply(0,0,0,state_all_1);
                        register_time_6.apply(0,11,ingress_global_time_2,timeout_1);
                        }
                       
                    // }
                    else if(signatureNow==5){
                        // if(signatureNow2==5){
                        register_state_5.apply(1,0b0000100000000000,0,state_all);
                        register_time_5.apply(1,11,ingress_global_time_2_back_1,timeout_next_Switch5);
                        register_state_1.apply(0,0,0,state_all_0);
                        register_time_1.apply(0,11,ingress_global_time_2_back_1,timeout_0);
                        register_state_2.apply(0,0,0,state_all_1);
                        register_time_2.apply(0,11,ingress_global_time_2_back_1,timeout_1);
                    }else{
                        register_state_6.apply(1,0b0000100000000000,0,state_all);
                            register_time_6.apply(1,11,ingress_global_time_2_back_1,timeout_next_Switch6);
                        register_state_1.apply(0,0,0,state_all_0);
                        register_time_1.apply(0,11,ingress_global_time_2_back_1,timeout_0);
                        register_state_2.apply(0,0,0,state_all_1);
                        register_time_2.apply(0,11,ingress_global_time_2_back_1,timeout_1);
                    }

                        // register_state_1.apply(0,0,0,state_all_0);
                        // register_time_1.apply(0,11,ingress_global_time_2_back_1,timeout_0);
                        // register_state_2.apply(0,0,0,state_all_1);
                        // register_time_2.apply(0,11,ingress_global_time_2_back_1,timeout_1);
                    // }
                            
                    store_state_0= (register_state_t)(state_all_0[10:10]);
                    store_state_1= (register_state_t)(state_all_1[10:10]);
                    check_neighbor_state_0.apply();
                    check_neighbor_state_1.apply();
                    // if(neighbor_2!=0){ 
                    // DIGEST_CHECK(2)
                    // DIGEST_CHECK(3)
                    // }

                    // //to resubmit the packet
                    // ig_intr_dprsr_md.resubmit_type = 1;
                
            } 
            // else if (hdr.port_down.isValid()){
            //          @stage(0){port_down_table.apply();
            //             reg_table_key_monitered =  (reg_table_key_t) hdr.heartbeat.Monitored_switch;
            //             store_port_down_time_reg_action.execute(reg_table_key_monitered);
            //          }
            //     }
            else 
            if(hdr.heartbeat.isValid()){
                // if(hdr.heartbeat.state==1){
                //      @stage(0){
                //         // neighbor_1 = (bit<4>) hdr.heartbeat.signature;
                //         meta.port_status.error_switch_1= (error_switch_t)hdr.heartbeat.signature;
                //         ig_intr_dprsr_md.digest_type =1;
                //             drop();
                //      }
                // }
                // else {
                    // reg_table_key_t neighbor=(reg_table_key_t)neighbor_##x##;    
                    if(hdr.heartbeat.heartbeat_type==ACK){
                        //reback the packets
                        // heart_back.apply();
                        @stage(0){heart_back_action();}
                        // get_neighbor_id_and_state();
                        //收到ACK数据：q包
                        //get the reback packets, update the signature neighbor's alive state

                        // get_mask.apply(hdr,meta);
                        get_mask_control.apply(signatureNow,maskNow);

                        if(signatureNow2==1){
                                @stage(0){register_state_1.apply(1,0b0000100000000000,1,read_pad_state_ack_1);
                                    register_time_1.apply(1,11,ingress_global_time_2_back_2,read_pad_time_ack_1);
                                    }
                            register_state_5.apply(1,maskNow,store_state_0,read_pad_state_ack_5);
                            register_time_5.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_ack_5);
                            register_state_6.apply(1,maskNow,store_state_0,read_pad_state_ack_6);
                            register_time_6.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_ack_6);
                        }else  if(signatureNow2==2){
                               
                            @stage(0){register_state_2.apply(1,0b0000100000000000,1,read_pad_state_ack_2);
                                    register_time_2.apply(1,11,ingress_global_time_2,read_pad_time_ack_2);
                                }
                            register_state_5.apply(1,maskNow,store_state_0,read_pad_state_ack_5);
                            register_time_5.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_ack_5);
                            register_state_6.apply(1,maskNow,store_state_0,read_pad_state_ack_6);
                            register_time_6.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_ack_6);
                                
                        
                        }
                         else if(signatureNow2==5){
                                    @stage(0){register_state_5.apply(1,0b0000100000000000,1,read_pad_state_5);
                                        register_time_5.apply(1,11,ingress_global_time_2_back_2,read_pad_time_5); 
                                        
                                  }
                                   register_state_1.apply(1,maskNow,store_state_0,read_pad_state_1);
                            register_time_1.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_1);
                            
                            register_state_2.apply(1,maskNow,store_state_0,read_pad_state_2);
                            register_time_2.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_2);

                        }else if (signatureNow2==6){
                            
                                    @stage(0){register_state_6.apply(1,0b0000100000000000,1,read_pad_state_6);
                                        register_time_6.apply(1,11,ingress_global_time_2_back_2,read_pad_time_6);}

                                   register_state_1.apply(1,maskNow,store_state_0,read_pad_state_1);
                            register_time_1.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_1);
                            
                            register_state_2.apply(1,maskNow,store_state_0,read_pad_state_2);
                            register_time_2.apply(1,signatureNow,ingress_global_time_2_back_2,read_pad_time_2);
                            
                           
                        }
                        
                        // get_neighbor_id_and_state();
                        // reg_table_key_monitered= (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                        
                    }
                    else{
                    //get the reback packets, update the monitered neighbor's alive state
                        reg_table_key_monitered= (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                        reg_table_key_monitered2= (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                        if(reg_table_key_monitered==1){
                             @stage(0){
                                register_state_1.apply(1,0b0000100000000000,1,read_pad_state_reback_1);
                                       register_time_1.apply(1,11,1,ingress_global_time_2_back_3,read_pad_time_reback_1,read_pad_time_reback_11);
                                }
                        }

                        else if(reg_table_key_monitered==2){
                             @stage(0){
                                register_state_2.apply(1,0b0000100000000000,1,read_pad_state_reback_2);
                                       register_time_2.apply(1,11,1,ingress_global_time_2_back_3,read_pad_time_reback_2,read_pad_time_reback_21);
                                       }
                        }

                     else if(reg_table_key_monitered==5){
                                register_state_5.apply(1,0b0000100000000000,1,read_pad_state_reback_5);
                                       register_time_5.apply(1,11,1,ingress_global_time_2_back_3,read_pad_time_reback_5,read_pad_time_reback_51);
                        }

                        else if(reg_table_key_monitered==6){
                                register_state_6.apply(1,0b0000100000000000,1,read_pad_state_reback_6);
                                       register_time_6.apply(1,11,1,ingress_global_time_2_back_3,read_pad_time_reback_6,read_pad_time_reback_61);
                        }
                       
                        drop();
                    }
            }
            else{
                //normal forwarding
                @stage(0){forward_table.apply();}
                // bit<9> ingress_port=ig_intr_md.ingress_port;
                // reg_table_key_t next_switch_reg_key=(reg_table_key_t)next_Switch;
                // if(next_Switch_state1==0){
                // getNextState_ALL.apply();
                
                if(next_switch_reg_key_1==1){
                    register_state_1.apply(0,1,0,state_all1);
                    register_time_1.apply(3,11,5,ingress_global_time_2_back_4,timeout_forward_Switch0,timeout_forward_Switch1);
                    // register_time_1.apply(0,5,ingress_global_time_2_back_4,timeout_forward_Switch1);
                    // register_time_1.apply(0,6,ingress_global_time_2,timeout_next_Switch3);
                }

                else if(next_switch_reg_key_1==2){
                    register_state_2.apply(0,1,0,state_all2);
                    register_time_2.apply(3,11,5,ingress_global_time_2_back_4,timeout_forward_Switch0,timeout_forward_Switch1);
                    // register_time_2.apply(0,5,ingress_global_time_2_back_4,timeout_forward_Switch1);
                    // register_time_2.apply(0,6,ingress_global_time_2,timeout_next_Switch3);
                    }
                else if(next_switch_reg_key_1==5){
                    register_state_5.apply(0,1,0,state_all5);
                    register_time_5.apply(3,11,1,ingress_global_time_2_back_4,timeout_forward_Switch0,timeout_forward_Switch1);
                    // register_time_5.apply(0,1,ingress_global_time_2_back_4,timeout_forward_Switch1);
                    // register_time_5.apply(0,2,ingress_global_time_2,timeout_next_Switch3);
                    // register_time_5.apply(0,9,ingress_global_time_2,timeout_next_Switch4);
                    // register_time_5.apply(0,10,ingress_global_time_2,timeout_next_Switch5);

                    }

                else if(next_switch_reg_key_1==6){
                    register_state_6.apply(0,1,0,state_all6);
                    register_time_6.apply(3,11,1,ingress_global_time_2_back_4,timeout_forward_Switch0,timeout_forward_Switch1);
                    // register_time_6.apply(0,1,ingress_global_time_2_back_4,timeout_forward_Switch1);
                    // register_time_6.apply(0,2,ingress_global_time_2,timeout_next_Switch3);
                    // register_time_6.apply(0,9,ingress_global_time_2,timeout_next_Switch4);
                    // register_time_6.apply(0,10,ingress_global_time_2,timeout_next_Switch5);

                    }

                
               
                tbl_get_value_state.apply();    //get state_all
                next_switch_state_all=(register_state_t)state_all[10:10];
                // stateInput=state_all;
                getNeighborState_table.apply();
                getNeighborState_table_1.apply();
                // getNeighborState_table_2.apply();
                // getNeighborState_table_3.apply();

                    // //to resubmit the packet
                    // ig_intr_dprsr_md.resubmit_type = 1;
              //     //from the detection switch
                //     next_Switch_state1 =(register_state_t)state_all[10:10];//从右边数第11位
                // //     //from itself
                //     next_Switch_state2 =(register_state_t) state_all[9:0];//todo

                //     //from common neighbor_switch
                //     //todo
                // next_Switch_state= (register_state_t)(next_Switch_state1 + next_Switch_state2);
                // if(next_switch_state_all<2){
                //     if(timeout_next_Switch1==1 && timeout_next_Switch2==1 ){  
                        change_port_table.apply();
                //     }
                // }
            
            }
        // }else{
        //     @stage(0){forward_table.apply();}
        //         // bit<9> ingress_port=ig_intr_md.ingress_port;
        //         // reg_table_key_t next_switch_reg_key=(reg_table_key_t)next_Switch;
        //         // if(next_Switch_state1==0){
        //         // getNextState_ALL.apply();
                
        //         if(next_switch_reg_key==1){
        //             // register_state_1.apply(0,1,0,state_all1);
        //             // register_time_1.apply(0,11,ingress_global_time_2,timeout_next_Switch1);
        //             register_time_1.apply(0,5,ingress_global_time_2,timeout_next_Switch2);
        //             register_time_1.apply(0,6,ingress_global_time_2,timeout_next_Switch3);
        //         }

        //         else if(next_switch_reg_key==2){
        //             // register_state_2.apply(0,1,0,state_all2);
        //             // register_time_2.apply(0,11,ingress_global_time_2,timeout_next_Switch1);
        //             register_time_2.apply(0,5,ingress_global_time_2,timeout_next_Switch2);
        //             register_time_2.apply(0,6,ingress_global_time_2,timeout_next_Switch3);
        //             }
        //         else if(next_switch_reg_key_1==5){
        //             // register_state_5.apply(0,1,0,state_all5);
        //             // register_time_5.apply(0,11,ingress_global_time_2,timeout_next_Switch1);
        //             register_time_5.apply(0,1,ingress_global_time_2,timeout_next_Switch2);
        //             register_time_5.apply(0,2,ingress_global_time_2,timeout_next_Switch3);
                   
        //             }

        //         else if(next_switch_reg_key_1==6){
        //             // register_state_6.apply(0,1,0,state_all6);
        //             // register_time_6.apply(0,11,ingress_global_time_2,timeout_next_Switch1);
        //             register_time_6.apply(0,1,ingress_global_time_2,timeout_next_Switch2);
        //             register_time_6.apply(0,2,ingress_global_time_2,timeout_next_Switch3);
        //             // register_time_6.apply(0,9,ingress_global_time_2,timeout_next_Switch4);
        //             // register_time_6.apply(0,10,ingress_global_time_2,timeout_next_Switch5);

        //             }
        //     }
            

        }  
    }
    
              
