
 #ifndef NEIGHBOR_TIME_REG
        #define NEIGHBOR_TIME_REG(n,m)  \
            Register<bit<32>, reg_table_key_t>(node_num)neighbor_time_reg_##n##_##m##;\
            RegisterAction<bit<32>, reg_table_key_t, bit<1>>(neighbor_time_reg_##n##_##m##)        \
            store_neighbor_time_reg_##n##_##m##_action = {       \
                void apply(inout bit<32> value){ \
            value = ingress_global_time_2;     \
                }         \
            }; \
            RegisterAction<bit<32>, reg_table_key_t,bit<1>>(neighbor_time_reg_##n##_##m##)         \
            check_neighbor_time_reg_##n##_##m##_action = {       \
                void apply(inout bit<32> value, out bit<1> read_value){           \
            bit<32> ingress_global_time_dur = ingress_global_time_2-value;   \
            if(ingress_global_time_dur>time_duration_threshold){    \
                read_value =1;  \
            }else{  \
                read_value=0;   \
            }   \
                }   \
            };
        #endif

        NEIGHBOR_TIME_REG(1,5)
        NEIGHBOR_TIME_REG(1,6)
        NEIGHBOR_TIME_REG(1,11)
        NEIGHBOR_TIME_REG(2,5)
        NEIGHBOR_TIME_REG(2,6)
        NEIGHBOR_TIME_REG(2,11)
        NEIGHBOR_TIME_REG(5,1)
        NEIGHBOR_TIME_REG(5,2)
        NEIGHBOR_TIME_REG(5,9)
        NEIGHBOR_TIME_REG(5,10)
        NEIGHBOR_TIME_REG(5,11)
        NEIGHBOR_TIME_REG(6,1)
        NEIGHBOR_TIME_REG(6,2)
        NEIGHBOR_TIME_REG(6,9)
        NEIGHBOR_TIME_REG(6,10)
        NEIGHBOR_TIME_REG(6,11)

        NEIGHBOR_TIME_REG(9,5)
        NEIGHBOR_TIME_REG(9,6)
        NEIGHBOR_TIME_REG(9,7)
        NEIGHBOR_TIME_REG(9,8)
        NEIGHBOR_TIME_REG(9,11)

        NEIGHBOR_TIME_REG(10,5)
        NEIGHBOR_TIME_REG(10,6)
        NEIGHBOR_TIME_REG(10,7)
        NEIGHBOR_TIME_REG(10,8)
        NEIGHBOR_TIME_REG(10,11)
        NEIGHBOR_TIME_REG(7,3)
        NEIGHBOR_TIME_REG(7,4)
        NEIGHBOR_TIME_REG(7,9)
        NEIGHBOR_TIME_REG(7,10)
        NEIGHBOR_TIME_REG(7,11)    
        NEIGHBOR_TIME_REG(8,3)
        NEIGHBOR_TIME_REG(8,4)
        NEIGHBOR_TIME_REG(8,9)
        NEIGHBOR_TIME_REG(8,10)
        NEIGHBOR_TIME_REG(8,11)      
        NEIGHBOR_TIME_REG(3,7)
        NEIGHBOR_TIME_REG(3,8)
        NEIGHBOR_TIME_REG(3,11)
        NEIGHBOR_TIME_REG(4,7)
        NEIGHBOR_TIME_REG(4,8)
        NEIGHBOR_TIME_REG(4,11)

        // #ifndef NEIGHBOR_STATE_REG
        // #define NEIGHBOR_STATE_REG(n,m)  \
        //     Register<state_string_t, reg_table_key_t> (reg_table_size) neighbor_alive_state_string_reg_##n##_##m##;\
        //     RegisterAction<state_string_t, reg_table_key_t,state_string_t>(neighbor_alive_state_string_reg_##n##_##m##)\
        //     update_neighbor_alive_state_string_reg_##n##_##m##_action={\
        //         void apply(inout state_string_t value, out state_string_t read_value){\
        //             value = ALIVE;\
        //         }\
        //     };\
        //     RegisterAction<state_string_t, reg_table_key_t,state_string_t>(neighbor_alive_state_string_reg_##n##_##m##)\
        //     updateN_neighbor_alive_state_string_reg_##n##_##m##_action={\
        //         void apply(inout state_string_t value, out state_string_t read_value){\
        //             value = NOALIVE;  \
        //         }\
        //     };\
        //     RegisterAction<state_string_t, reg_table_key_t,state_string_t>(neighbor_alive_state_string_reg_##n##_##m##)\
        //     get_neighbor_alive_state_string_reg_##n##_##m##_action={\
        //         void apply(inout state_string_t value, out state_string_t read_value){\
        //             read_value = value;\
        //         }\
        //     };
        // #endif

        // NEIGHBOR_STATE_REG(1,5)
        // NEIGHBOR_STATE_REG(1,6)
        // NEIGHBOR_STATE_REG(1,11)
        // NEIGHBOR_STATE_REG(2,5)
        // NEIGHBOR_STATE_REG(2,6)
        // NEIGHBOR_STATE_REG(2,11)
        // NEIGHBOR_STATE_REG(5,1)
        // NEIGHBOR_STATE_REG(5,2)
        // NEIGHBOR_STATE_REG(5,9)
        // NEIGHBOR_STATE_REG(5,10)
        // NEIGHBOR_STATE_REG(5,11)
        // NEIGHBOR_STATE_REG(6,1)
        // NEIGHBOR_STATE_REG(6,2)
        // NEIGHBOR_STATE_REG(6,9)
        // NEIGHBOR_STATE_REG(6,10)
        // NEIGHBOR_STATE_REG(6,11)

        // NEIGHBOR_STATE_REG(9,5)
        // NEIGHBOR_STATE_REG(9,6)
        // NEIGHBOR_STATE_REG(9,7)
        // NEIGHBOR_STATE_REG(9,8)
        // NEIGHBOR_STATE_REG(9,11)

        // NEIGHBOR_STATE_REG(10,5)
        // NEIGHBOR_STATE_REG(10,6)
        // NEIGHBOR_STATE_REG(10,7)
        // NEIGHBOR_STATE_REG(10,8)
        // NEIGHBOR_STATE_REG(10,11)
        // NEIGHBOR_STATE_REG(7,3)
        // NEIGHBOR_STATE_REG(7,4)
        // NEIGHBOR_STATE_REG(7,9)
        // NEIGHBOR_STATE_REG(7,10)
        // NEIGHBOR_STATE_REG(7,11)    
        // NEIGHBOR_STATE_REG(8,3)
        // NEIGHBOR_STATE_REG(8,4)
        // NEIGHBOR_STATE_REG(8,9)
        // NEIGHBOR_STATE_REG(8,10)
        // NEIGHBOR_STATE_REG(8,11)      
        // NEIGHBOR_STATE_REG(3,7)
        // NEIGHBOR_STATE_REG(3,8)
        // NEIGHBOR_STATE_REG(3,11)
        // NEIGHBOR_STATE_REG(4,7)
        // NEIGHBOR_STATE_REG(4,8)
        // NEIGHBOR_STATE_REG(4,11)


// action add(inout bit<8> stateOut,bit<8> stateIn){
//     next_switch_state_all=stateOut+stateIn;
// }
// register_state_t state;
// #define tbl_get_neighbor_state(n)\
//     action tbl_get_neighbor_state_##n##(){\
//         state = (register_state_t)(stateInput[##n##:##n##]);\
//         add(next_switch_state_all,state);\
//     }

// tbl_get_neighbor_state(1)
// tbl_get_neighbor_state(2)
// tbl_get_neighbor_state(3)
// tbl_get_neighbor_state(4)
// tbl_get_neighbor_state(5)
// tbl_get_neighbor_state(6)
// tbl_get_neighbor_state(7)
// tbl_get_neighbor_state(8)
// tbl_get_neighbor_state(9)
// tbl_get_neighbor_state(10)
// tbl_get_neighbor_state(11)

// table getNeighborState_table {
//         key = {
//         neighbor_0 : exact;
//     }
//     actions = {
//         tbl_get_neighbor_state_1;
//         tbl_get_neighbor_state_2;
//         tbl_get_neighbor_state_3;
//         tbl_get_neighbor_state_4;
//         tbl_get_neighbor_state_5;
//         tbl_get_neighbor_state_6;
//         tbl_get_neighbor_state_7;
//         tbl_get_neighbor_state_8;
//         tbl_get_neighbor_state_9;
//         tbl_get_neighbor_state_10;
//         tbl_get_neighbor_state_11;
//     }
//     const entries = {
//         1: tbl_get_neighbor_state_1;
//         2: tbl_get_neighbor_state_2;
//         3: tbl_get_neighbor_state_3;
//         4: tbl_get_neighbor_state_4;
//         5: tbl_get_neighbor_state_5;
//         6: tbl_get_neighbor_state_6;
//         7: tbl_get_neighbor_state_7;
//         8: tbl_get_neighbor_state_8;
//         9: tbl_get_neighbor_state_9;
//         10: tbl_get_neighbor_state_10;
//         11: tbl_get_neighbor_state_11;
//     }
//     size = 16;
// }
// table getNeighborState_table_1 {
//         key = {
//         neighbor_1 : exact;
//     }
//     actions = {
//         tbl_get_neighbor_state_1;
//         tbl_get_neighbor_state_2;
//         tbl_get_neighbor_state_3;
//         tbl_get_neighbor_state_4;
//         tbl_get_neighbor_state_5;
//         tbl_get_neighbor_state_6;
//         tbl_get_neighbor_state_7;
//         tbl_get_neighbor_state_8;
//         tbl_get_neighbor_state_9;
//         tbl_get_neighbor_state_10;
//         tbl_get_neighbor_state_11;
//     }
//     const entries = {
//         1: tbl_get_neighbor_state_1;
//         2: tbl_get_neighbor_state_2;
//         3: tbl_get_neighbor_state_3;
//         4: tbl_get_neighbor_state_4;
//         5: tbl_get_neighbor_state_5;
//         6: tbl_get_neighbor_state_6;
//         7: tbl_get_neighbor_state_7;
//         8: tbl_get_neighbor_state_8;
//         9: tbl_get_neighbor_state_9;
//         10: tbl_get_neighbor_state_10;
//         11: tbl_get_neighbor_state_11;
//     }
//     size = 16;
// }
// table getNeighborState_table_2 {
//         key = {
//         neighbor_2 : exact;
//     }
//     actions = {
//         tbl_get_neighbor_state_1;
//         tbl_get_neighbor_state_2;
//         tbl_get_neighbor_state_3;
//         tbl_get_neighbor_state_4;
//         tbl_get_neighbor_state_5;
//         tbl_get_neighbor_state_6;
//         tbl_get_neighbor_state_7;
//         tbl_get_neighbor_state_8;
//         tbl_get_neighbor_state_9;
//         tbl_get_neighbor_state_10;
//         tbl_get_neighbor_state_11;
//     }
//     const entries = {
//         1: tbl_get_neighbor_state_1;
//         2: tbl_get_neighbor_state_2;
//         3: tbl_get_neighbor_state_3;
//         4: tbl_get_neighbor_state_4;
//         5: tbl_get_neighbor_state_5;
//         6: tbl_get_neighbor_state_6;
//         7: tbl_get_neighbor_state_7;
//         8: tbl_get_neighbor_state_8;
//         9: tbl_get_neighbor_state_9;
//         10: tbl_get_neighbor_state_10;
//         11: tbl_get_neighbor_state_11;
//     }
//     size = 16;
// }
// table getNeighborState_table_3 {
//         key = {
//         neighbor_3 : exact;
//     }
//     actions = {
//         tbl_get_neighbor_state_1;
//         tbl_get_neighbor_state_2;
//         tbl_get_neighbor_state_3;
//         tbl_get_neighbor_state_4;
//         tbl_get_neighbor_state_5;
//         tbl_get_neighbor_state_6;
//         tbl_get_neighbor_state_7;
//         tbl_get_neighbor_state_8;
//         tbl_get_neighbor_state_9;
//         tbl_get_neighbor_state_10;
//         tbl_get_neighbor_state_11;
//     }
//     const entries = {
//         1: tbl_get_neighbor_state_1;
//         2: tbl_get_neighbor_state_2;
//         3: tbl_get_neighbor_state_3;
//         4: tbl_get_neighbor_state_4;
//         5: tbl_get_neighbor_state_5;
//         6: tbl_get_neighbor_state_6;
//         7: tbl_get_neighbor_state_7;
//         8: tbl_get_neighbor_state_8;
//         9: tbl_get_neighbor_state_9;
//         10: tbl_get_neighbor_state_10;
//         11: tbl_get_neighbor_state_11;
//     }
//     size = 16;
// }
#define tbl_set_digest(x)\
    action set_digest_##x##(){\
        meta.port_status.error_switch_##x##= (bit<8>) neighbor_##x##;\
        ig_intr_dprsr_md.digest_type =1;\
    }
tbl_set_digest(0)
tbl_set_digest(1)
tbl_set_digest(2)
tbl_set_digest(3)   
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
#define tbl_check_neighbor_state(x)\
    table check_neighbor_state_##x## {\
        key = {\
            timeout_##x## : exact;\
            store_state_##x##:exact;\
        }\
        actions = {\
            set_digest_##x##;\
            setHeaderState_##x##;\
        }\
        const entries = {\
            (1,0):set_digest_##x##;\
        }\
        const default_action = setHeaderState_##x##();\
        size = 8;\
    }
tbl_check_neighbor_state(0)
tbl_check_neighbor_state(1)
tbl_check_neighbor_state(2)
tbl_check_neighbor_state(3) 

action add(inout register_state_t a,inout register_state_t b,inout register_state_t c){
    a=a+b+c;
}
