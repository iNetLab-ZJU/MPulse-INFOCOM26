    //the table of neighbor alive state (key-states)
    #ifndef GEN_REGISTER_TIME
    #define GEN_REGISTER_TIME(n)                                                        \
        Register<time_t, reg_table_key_t>(node_num) neighbor_time_##n##_reg;            \
        RegisterAction<time_t, reg_table_key_t, bit<1>>(neighbor_time_##n##_reg)        \
        store_neighbor_time_##n##_reg_action = {                                        \
            void apply(inout time_t value){                                             \
                    value.time_1 = (bit<32>)ig_intr_prsr_md.global_tstamp[47:32];                 \
                    value.time_2 = ig_intr_prsr_md.global_tstamp[31:0];                           \
            }                                                                           \
        };                                                                              \
        RegisterAction<time_t, reg_table_key_t,bit<1>>(neighbor_time_##n##_reg)         \
        check_neighbor_time_##n##_reg_action = {                                        \
            void apply(inout time_t value, out bit<1> read_value){                      \
                if(value.time_1 == (bit<32>)ig_intr_prsr_md.global_tstamp[47:32]){                \
                    bit<32> ingress_global_time_dur = ig_intr_prsr_md.global_tstamp[31:0]-value.time_2;   \
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
    #endif



    #define GEN_NEIGHBOR_STATE_STRING_REGISTER(n)  \   
        Register<bit<32>, reg_table_key_t> (reg_table_size) neighbor_alive_state_string_##n##_reg;\
        RegisterAction<bit<32>, reg_table_key_t,bit<32>>(neighbor_alive_state_string_##n##_reg)\
        update_neighbor_alive_state_string_##n##_reg_action={\
            void apply(inout bit<32> value, out bit<32> read_value){\
                value = value | mask_##n##;  \
                read_value = value;\
            }\
        };\
        RegisterAction<bit<32>, reg_table_key_t,bit<32>>(neighbor_alive_state_string_##n##_reg)\
        updateN_neighbor_alive_state_string_##n##_reg_action={\
            void apply(inout bit<32> value, out bit<32> read_value){\
                value = value & ~mask_##n##;  \
                read_value = value;\
            }\
        };\
        RegisterAction<bit<32>, reg_table_key_t,bit<32>>(neighbor_alive_state_string_##n##_reg)\
        get_neighbor_alive_state_string_##n##_reg_action={\
            void apply(inout bit<32> value, out bit<32> read_value){\
                read_value = value;\
            }\
        };


