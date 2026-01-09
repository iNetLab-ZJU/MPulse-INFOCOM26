
control GET_MASK_CONTROL(
    in reg_table_key_t signatureNow,
    out state_string_t mask_return)
{
    // state_string_t mask_return;
    action tbl_get_mask_1 () {
        mask_return = 0b0000000000000010;
    }
    action tbl_get_mask_2 () {
        mask_return = 0b0000000000000100;
    }
    action tbl_get_mask_3 () {
        mask_return = 0b0000000000001000;
    }
    action tbl_get_mask_4 () {
        mask_return = 0b0000000000010000;
    }
    action tbl_get_mask_5 () {
        mask_return = 0b0000000000100000;
    }
    action tbl_get_mask_6 () {
        mask_return = 0b0000000001000000;
    }
    action tbl_get_mask_7 () {
        mask_return = 0b0000000010000000;
    }
    action tbl_get_mask_8 () {
        mask_return = 0b0000000100000000;
    }
    action tbl_get_mask_9 () {
        mask_return = 0b0000001000000000;
    }
    action tbl_get_mask_10 () {
        mask_return = 0b0000010000000000;
    }
    action tbl_get_mask_11 () {
        mask_return = 0b0000100000000000;
    }
    table tbl_get_mask {
        key = {
            signatureNow : exact;
        }
        actions = {
            tbl_get_mask_1;
            tbl_get_mask_2;
            tbl_get_mask_3;
            tbl_get_mask_4;
            tbl_get_mask_5;
            tbl_get_mask_6;
            tbl_get_mask_7;
            tbl_get_mask_8;
            tbl_get_mask_9;
            tbl_get_mask_10;
            tbl_get_mask_11;
        }
        const entries = {
            1: tbl_get_mask_1;
            2: tbl_get_mask_2;
            3: tbl_get_mask_3;
            4: tbl_get_mask_4;
            5: tbl_get_mask_5;
            6: tbl_get_mask_6;
            7: tbl_get_mask_7;
            8: tbl_get_mask_8;
            9: tbl_get_mask_9;
            10: tbl_get_mask_10;
            11: tbl_get_mask_11;
        }
        size = 16;
    }
    apply {
        tbl_get_mask.apply();
    }
}
// #define MODIFY_REGISTER_STATE(n)
control MODIFY_REGISTER_STATE(
    in bit<1> store_or_get,
    in reg_table_key_t reg_table_key,
    in state_string_t maskNew,
    in register_state_t state,
    inout state_string_t state_string_value
){
        Register<state_string_t, reg_table_key_t> (reg_table_size) neighbor_alive_state_string_reg;
        RegisterAction<state_string_t, reg_table_key_t,state_string_t>(neighbor_alive_state_string_reg)
        update_neighbor_alive_state_string_reg_action={
            void apply(inout state_string_t value, out state_string_t read_value){
                value = value | maskNew;  
                read_value = value;
            }
        };
        RegisterAction<state_string_t, reg_table_key_t,state_string_t>(neighbor_alive_state_string_reg)
        updateN_neighbor_alive_state_string_reg_action={
            void apply(inout state_string_t value, out state_string_t read_value){
                value = value & ~maskNew;  
                read_value = value;
            }
        };
        // RegisterAction<state_string_t, reg_table_key_t,state_string_t>(neighbor_alive_state_string_reg)
        // get_neighbor_alive_state_string_reg_action={
        //     void apply(inout state_string_t value, out state_string_t read_value){
        //         read_value = value;
        //     }
        // };
        apply {
            if(store_or_get>0){
                if(state==0){
                    updateN_neighbor_alive_state_string_reg_action.execute(1);
                }else{
                    update_neighbor_alive_state_string_reg_action.execute(1);
                }
            }else{
                state_string_value = updateN_neighbor_alive_state_string_reg_action.execute(1);
            }
        }
}


// #define MODIFY_REGISTER_TIME(n)
control MODIFY_REGISTER_TIME(
    in bit<1> store_or_get,
    in reg_table_key_t reg_table_key,
    in bit<32> ingress_time,
    inout bit<1> timeout_next_Switch
){
        Register<bit<32>, reg_table_key_t>(node_num) neighbor_time_reg;            
        RegisterAction<bit<32>, reg_table_key_t, bit<1>>(neighbor_time_reg)        
        store_neighbor_time_reg_action = {                                        
            void apply(inout bit<32> value){                                             
                    value = ingress_time;                           
            }                                                                           
        };                                                                              
        RegisterAction<bit<32>, reg_table_key_t,bit<1>>(neighbor_time_reg)         
        check_neighbor_time_reg_action = {                                        
            void apply(inout bit<32> value, out bit<1> read_value){                      
                    bit<32> ingress_global_time_dur = ingress_time-value;   
                    if(ingress_global_time_dur>time_duration_threshold){    
                        read_value =1;  
                    }else{  
                        read_value=0;   
                    }   
            }   
        };
        apply {
            //0 get value
            if(store_or_get==1){
                store_neighbor_time_reg_action.execute(reg_table_key);
            }else{
                 timeout_next_Switch = check_neighbor_time_reg_action.execute(reg_table_key);
            }
        }
}

control GET_REGISTER_STATE(
    in bit<1> store_or_get,
    in reg_table_key_t reg_table_key,
    in state_string_t maskNew,
    in register_state_t state,
    inout state_string_t state_string_value,
    in bit<32> ingress_time,
    inout bit<1> timeout_next_Switch
){

    MODIFY_REGISTER_STATE() register_state_1;
    MODIFY_REGISTER_TIME() register_time_1;
    apply{
        if(store_or_get==1){
            if(reg_table_key==11){
                register_state_1.apply(1,11,0b0000100000000000,state,state_string_value);
                register_time_1.apply(1,11,ingress_time,timeout_next_Switch);       
            }else{
                register_state_1.apply(1,reg_table_key,maskNew,state,state_string_value);
                register_time_1.apply(1,reg_table_key,ingress_time,timeout_next_Switch); 
            }
        }else{
            if(reg_table_key==11){
                register_state_1.apply(0,11,0,0,state_string_value);
                register_time_1.apply(0,11,ingress_time,timeout_next_Switch);
            }else{
                register_state_1.apply(0,reg_table_key,0,0,state_string_value);
                register_time_1.apply(0,reg_table_key,ingress_time,timeout_next_Switch);
            }
        }
       
    }

}
