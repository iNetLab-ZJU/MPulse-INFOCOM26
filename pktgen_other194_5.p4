control SwitchIngress_5
(
            inout headers hdr, 
            inout  ingress_metadata_t meta,
            in ingress_intrinsic_metadata_t ig_intr_md,
            in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
            inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
            inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


        bit<32> neighbor_list=0;
        bit<4> flag=0;
        reg_table_key_t next_switch_reg_key;
        bit<48> ingress_global_time=ig_intr_prsr_md.global_tstamp;
        bit<32> ingress_global_time_1;
        bit<32> ingress_global_time_2;
        bit<8> flow_id;
        bit<2> pipe;
        bit<32> state_all; 
        bit<4> neighbor_num=4;
        bit<4> neighbor_0;
        bit<4> neighbor_1;
        bit<4> neighbor_2;
        bit<4> neighbor_3;
        bit<1> ifTimeOut_0=0;
        bit<1> ifTimeOut_1=0;
        bit<1> ifTimeOut_2=0;
        bit<32> mask_1;
                        bit<32> mask_2;
                        
        bit<32> mask_11;
        reg_table_key_t neighbor0=0;
        reg_table_key_t neighbor1=0;
        reg_table_key_t neighbor2=0;
        reg_table_key_t neighbor3=0;
        bit<32> down_time_count=0;
        bit<1> alive_flag=0;
        bit<4>  neighbor_count=0;
        bit<4>  neighbor_count_2=0;
        register_state_t store_state=1;
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
        register_state_t store_state_1=0;
        register_state_t store_state_2=0;
        register_state_t store_state_3=0;
        register_state_t store_state_4=0;
        register_state_t store_state_5=0;
        register_state_t store_state_6=0;
        register_state_t store_state_7=0;
        register_state_t store_state_8=0;
        register_state_t store_state_9=0;
        register_state_t store_state_10=0;
        register_state_t store_state_11=0;
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
        reg_table_key_t reg_table_key_monitered=0;
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
                value.time_1 = (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
                value.time_2 = ig_intr_prsr_md.global_tstamp[31:0];
            }
        };
        RegisterAction<time_t, reg_table_key_t,bit<1>>(port_down_time_reg)
        check_port_down_time_reg_action = {
            void apply(inout time_t value, out bit<1> read_value){
                if(value.time_1 == (bit<32>)ig_intr_prsr_md.global_tstamp[47:32]){
                    bit<32> ingress_global_time_dur = ig_intr_prsr_md.global_tstamp[31:0]-value.time_2;
                    if(ingress_global_time_dur>time_duration_threshold){
                        read_value =1;
                    }
                }
            }
        };

        Register<time_t, reg_table_key_t>(12) neighbor_time_reg;
        RegisterAction<time_t, reg_table_key_t, bit<1>>(neighbor_time_reg) 
        store_neighbor_time_reg_action = {
            void apply(inout time_t value){
                    value.time_1 = (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];
                    value.time_2 = ig_intr_prsr_md.global_tstamp[31:0];
            }
        };
        //todo: check the time
        RegisterAction<time_t, reg_table_key_t,bit<1>>(neighbor_time_reg)
        check_neighbor_time_reg_action = {
            void apply(inout time_t value, out bit<1> read_value){
                if(value.time_1 == (bit<32>)ig_intr_prsr_md.global_tstamp[47:32]){
                    bit<32> ingress_global_time_dur = ig_intr_prsr_md.global_tstamp[31:0]-value.time_2;
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
        #include "Ingress_register.p4"
        
                GEN_REGISTER_TIME(1)
                GEN_REGISTER_TIME(2)
        GEN_REGISTER_TIME(11)
        
                GEN_NEIGHBOR_STATE_STRING_REGISTER(1)
                GEN_NEIGHBOR_STATE_STRING_REGISTER(2)
        GEN_NEIGHBOR_STATE_STRING_REGISTER(11)
        action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1;
        }

        action change_port(PortId_t back_port) {
            ig_intr_tm_md.ucast_egress_port = back_port;
        }
        action l3_switch(PortId_t port,PortId_t nextSwitchId) {
            ig_intr_tm_md.ucast_egress_port = port;
            next_switch_reg_key=(reg_table_key_t)nextSwitchId;
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
            // hdr.heartbeat.setValid(); 
            // get_neighbor_id_and_state();   
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
            // hdr.neighborState[0].neighbor=neighbor_0;
            // hdr.neighborState[1].neighbor=neighbor_1;
            // hdr.neighborState[2].neighbor=neighbor_2;
            // hdr.neighborState[3].neighbor=neighbor_3;
            // hdr.heartbeat.state = 0;
        }
        action add_heartbeat_neighbor(){
            hdr.neighborState[0].neighbor=neighbor_0;
            hdr.neighborState[1].neighbor=neighbor_1;
            hdr.neighborState[2].neighbor=neighbor_2;
            hdr.neighborState[3].neighbor=neighbor_3;
        }

        action match(PortId_t port,signature_t signature,signature_t Monitored_switch) {
            ig_intr_tm_md.ucast_egress_port = port;
            signatureNow = (reg_table_key_t)signature;
            // Monitored_switch_now=(reg_table_key_t)Monitored_switch;
            // 自己检测到的信息
            getNeighborList((reg_table_key_t)signature);
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
            meta.port_status.error_switch_0= (error_switch_t)neighbor_0;
            ig_intr_dprsr_md.digest_type =1;
        }
        action carry_to_digest_1(){
            meta.port_status.error_switch_1= (error_switch_t)neighbor_1;
            ig_intr_dprsr_md.digest_type =1;
        }
        action carry_to_digest_2(){
            meta.port_status.error_switch_2= (error_switch_t)neighbor_2;
            ig_intr_dprsr_md.digest_type =1;
        }
        action carry_to_digest_3(){
            meta.port_status.error_switch_3= (error_switch_t)neighbor_3;
            ig_intr_dprsr_md.digest_type =1;
        }
        // action getResubmit(){
        //     neighbor0=(reg_table_key_t)meta.port_status.error_switch_0;
        //     neighbor1=(reg_table_key_t)meta.port_status.error_switch_1;
        //     neighbor2=(reg_table_key_t)meta.port_status.error_switch_2;
        //     neighbor3=(reg_table_key_t)meta.port_status.error_switch_3;
        // }

        action init_header_state(){
            hdr.neighborState[0].state=1;
            hdr.neighborState[1].state=1;
            hdr.neighborState[2].state=1;
            hdr.neighborState[3].state=1;
        }

        action getRegisterKeySignature(){
            reg_table_key=(reg_table_key_t) hdr.heartbeat.signature;
        }
        action getRegisterKeyMoniter(){
            reg_table_key = (reg_table_key_t) hdr.heartbeat.Monitored_switch;
        }
        
     
              
        //todo:
        // n : monitered switch id, signature:5
        #ifndef STORE_MONITERED_ALIVE_REG_ACTION
        #define STORE_MONITERED_ALIVE_REG_ACTION(n)\
                mask_##n## = (bit<32>)1 <<(5-1);\
                update_neighbor_alive_state_string_##n##_reg_action.execute(1);\
                store_neighbor_time_##n##_reg_action.execute(5);
        #endif

        #ifndef STORE_MONITERED_ALIVE_REG_ACTION_N
        #define STORE_MONITERED_ALIVE_REG_ACTION_N(n)\
                mask_##n## = (bit<32>)1 <<(5-1);\
                updateN_neighbor_alive_state_string_##n##_reg_action.execute(1);\
                store_neighbor_time_##n##_reg_action.execute(5);
        #endif
    
            // x:neighbor index n:neighbor's id;  s:signatureNow
            #ifndef STORE_MONITERED_ALIVE_REG_ACTION_X
            #define STORE_MONITERED_ALIVE_REG_ACTION_X(x,n,s)\
                    store_state_##n##=(register_state_t)hdr.neighborState[##x##].state;\
                    mask_##n##=(bit<32>)1 <<(##s##-1);\
                    store_neighbor_time_##n##_reg_action.execute(##s##);\
                    if(store_state_##n##==0){  \
                        updateN_neighbor_alive_state_string_##n##_reg_action.execute(1);\
                        meta.port_status.error_switch_##x##= ##n##;\
                        ig_intr_dprsr_md.digest_type =1;\
                    }else{\
                        update_neighbor_alive_state_string_##n##_reg_action.execute(1);\
                    }
            #endif
            //todo:
            // x:neighbor's index n:neighbor's id; 
            #ifndef GET_NEIGHBOR_ALIVE_REG_ACTION
            #define GET_NEIGHBOR_ALIVE_REG_ACTION(x,n,s)      \
                        state_all = get_neighbor_alive_state_string_##n##_reg_action.execute(1);\
                        store_state_##n##= (register_state_t) (state_all >> (##s##-1)) & 1;\
                        timeout_##x##=check_neighbor_time_##n##_reg_action.execute(##s##);\
                        if(timeout_##x##==1 && store_state_##n##==0){  \
                            meta.port_status.error_switch_##x##= ##n##;\
                            ig_intr_dprsr_md.digest_type =1;\
                        }else{  \
                            setHeaderState_##x##();   \
                        } 
            #endif

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
                    next_switch_reg_key:  exact;
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
                // if(ig_intr_md.resubmit_flag==0){
                    //This is the first pass of the ingress pipeline for this packet.
                    //if is timer packets
                    if (hdr.timer.isValid()) {
                        //同时将心跳包发给对应的交换机 init the intial information
                        timer_periodic.apply();
                        //被监测的交换机
                        reg_table_key_monitered = (reg_table_key_t)hdr.heartbeat.Monitored_switch;
                        //第一组数据包不读状态？
                        bit<1> batch_time = catch_batch_time_reg_action.execute((reg_table_key_t)hdr.heartbeat.Monitored_switch);
                        if(batch_time==0){
                            //初始各个邻居状态为1
                            init_header_state();
                            // stateM_2=1;
                            // @stage(4){store_neighbor_time_reg_action.execute(reg_table_key);}
                            //在本地检测寄存器中初始存储被检测节点的时间
              
     
                            
                    if(reg_table_key_monitered==1){
                        STORE_MONITERED_ALIVE_REG_ACTION_N(1);
                    }

                    else if(reg_table_key_monitered==2){
                        STORE_MONITERED_ALIVE_REG_ACTION_N(2);
                    }
              }else if (batch_time==1){
                    //其他的数据包读状态，看当前的邻居状态，存储在发给对应的交换机
                    meta.signature=(signature_t)signatureNow;                
                    //store the monitered switch's state
                    if(reg_table_key_monitered==11){
                        add_heartbeat_neighbor();
                        STORE_MONITERED_ALIVE_REG_ACTION_N(11);
                            
                GET_NEIGHBOR_ALIVE_REG_ACTION(0,1,5)

                GET_NEIGHBOR_ALIVE_REG_ACTION(1,2,5)
                    }else{
                        
                    if(reg_table_key_monitered==1){
                        STORE_MONITERED_ALIVE_REG_ACTION_N(1);
                    }

                    else if(reg_table_key_monitered==2){
                        STORE_MONITERED_ALIVE_REG_ACTION_N(2);
                    }
                        // between themself, they exchange the state of 11
                        neighbor_0=11;
                        neighbor_1=0;
                        neighbor_2=0;
                        neighbor_3=0;
                        hdr.neighborState[0].neighbor=11;
                        GET_NEIGHBOR_ALIVE_REG_ACTION(0, 11, 5);
                    }
                    // //to resubmit the packet
                    // ig_intr_dprsr_md.resubmit_type = 1;
                }
            } else if (hdr.port_down.isValid()){
                    port_down_table.apply();
                    reg_table_key_monitered =  (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                    store_port_down_time_reg_action.execute(reg_table_key_monitered);
                }
            else if(hdr.heartbeat.isValid()){
                if(hdr.heartbeat.state==1){
                    neighbor_1 = (bit<4>) hdr.heartbeat.signature;
                    carry_to_digest_1();
                    drop();
                }
                else {
                    // getKey_table.apply();
                    // reg_table_key_t neighbor=(reg_table_key_t)neighbor_##x##;    
                    if(hdr.heartbeat.heartbeat_type==ACK){
                        //reback the packets
                        // heart_back.apply();
                        heart_back_action();
                        // get_neighbor_id_and_state();
                        //收到ACK数据包
                        //get the reback packets, update the signature neighbor's alive state
                        signatureNow=(reg_table_key_t) hdr.heartbeat.signature;
                        if(signatureNow==11){
                            STORE_MONITERED_ALIVE_REG_ACTION(11);
                            // CHECK_AND_STORE_NEIGHBOR_STATUS(0,11)
                            
                STORE_MONITERED_ALIVE_REG_ACTION_X(0,1,5)

                STORE_MONITERED_ALIVE_REG_ACTION_X(1,2,5)
                        }
                    else if(signatureNow==1){
                        STORE_MONITERED_ALIVE_REG_ACTION(1);
                        STORE_MONITERED_ALIVE_REG_ACTION_X(0 , 11 , 1);
                    }

                    else if(signatureNow==2){
                        STORE_MONITERED_ALIVE_REG_ACTION(2);
                        STORE_MONITERED_ALIVE_REG_ACTION_X(1 , 11 , 2);
                    }
                        // get_neighbor_id_and_state();
                        // reg_table_key_monitered= (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                    }
              
     
            else{
                //get the reback packets, update the monitered neighbor's alive state
                reg_table_key_monitered= (reg_table_key_t) hdr.heartbeat.Monitored_switch;
                store_state=1;
                
                    if(reg_table_key_monitered==1){
                        STORE_MONITERED_ALIVE_REG_ACTION(1);
                    }

                    else if(reg_table_key_monitered==2){
                        STORE_MONITERED_ALIVE_REG_ACTION(2);
                    }
                    drop();
                    }
                    //to store the state of 
                   
                }
            }
            else{
                //normal forwarding
                forward_table.apply();
                // bit<9> ingress_port=ig_intr_md.ingress_port;
                // reg_table_key_t next_switch_reg_key=(reg_table_key_t)next_Switch;
                // if(next_Switch_state1==0){
                
                if(next_switch_reg_key==1){
                    state_all=  get_neighbor_alive_state_string_1_reg_action.execute(1);
                    timeout_next_Switch1 =check_neighbor_time_1_reg_action.execute(11);
                    timeout_next_Switch2 =check_neighbor_time_1_reg_action.execute(5);
                }

                else if(next_switch_reg_key==2){
                    state_all=  get_neighbor_alive_state_string_2_reg_action.execute(1);
                    timeout_next_Switch1 =check_neighbor_time_2_reg_action.execute(11);
                    timeout_next_Switch2 =check_neighbor_time_2_reg_action.execute(5);
                }
              // }
                //from the detection switch
                next_Switch_state1 =(register_state_t)state_all[10:10];//从右边数第11位
                //from itself
                next_Switch_state2 =(register_state_t) state_all[0:0];//todo

                //from common neighbor_switch
                //todo
                next_Switch_state= (register_state_t)(state_all[10:10] ++ state_all[0:0]);
                if(next_Switch_state==0){
                    if(timeout_next_Switch1==1 && timeout_next_Switch2==1 ){  
                        change_port_table.apply();
                    }
                }
            }
        // }
        // else{
        //     // This is the second pass of the ingress pipeline for this packet.
        //     // ingress_global_time= ig_intr_prsr_md.global_tstamp;
        //     //if is timer packets

        // }
        
        // No need for egress processing, skip it and use empty controls for egress.
        ig_intr_tm_md.bypass_egress = 1w1;

        
            }
        }
              
