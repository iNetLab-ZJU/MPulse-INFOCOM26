// todo:
    //index, signatureNow
    #ifndef CHECK_AND_STORE_NEIGHBOR_STATUS
    #define CHECK_AND_STORE_NEIGHBOR_STATUS( index,signatureN) \
            bit<4> NEIGHBOR##index## = hdr.neighborState[##index##].neighbor;\
            if (NEIGHBOR##index## == 5 && signatureN !=5) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 5 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 6 && signatureN !=6) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 6 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 7 && signatureN !=7) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 7 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 8 && signatureN !=8) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 8 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 11 && signatureN !=11) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 11, ##signatureN##); \
            }     
    #endif
    //index, signatureNow 05 16 27 38
    #ifndef CHECK_AND_STORE_NEIGHBOR_STATUS_SOLID
    #define CHECK_AND_STORE_NEIGHBOR_STATUS_SOLID( index,NEIGHBOR,signatureN) \
            bit<4> NEIGHBOR##index## = hdr.neighborState[##index##].neighbor;\
            if (index == 0 && signatureN !=5) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 5 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 6 && signatureN !=6) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 6 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 7 && signatureN !=7) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 7 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 8 && signatureN !=8) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 8 , ##signatureN##); \
            } else if (NEIGHBOR##index## == 11 && signatureN !=11) { \
                STORE_MONITERED_ALIVE_REG_ACTION_X(##index##, 11, ##signatureN##); \
            }     
    #endif   

//todo:
    #ifndef CHECK_AND_GET_NEIGHBOR_STATUS
    #define CHECK_AND_GET_NEIGHBOR_STATUS(neighbor, index, signatureN) \
        if(neighbor!=0){\
            if (neighbor == 5) { \
                GET_NEIGHBOR_ALIVE_REG_ACTION(##index##, 5 ,##signatureN##); \
            } else if (neighbor == 6) { \
                GET_NEIGHBOR_ALIVE_REG_ACTION(##index##, 6 ,##signatureN##); \
            } else if (neighbor == 7) { \
                GET_NEIGHBOR_ALIVE_REG_ACTION(##index##, 7 ,##signatureN##); \
            } else if (neighbor == 8) { \
                GET_NEIGHBOR_ALIVE_REG_ACTION(##index##, 8 ,##signatureN##); \
            } else if (neighbor == 11) { \
                GET_NEIGHBOR_ALIVE_REG_ACTION(##index##, 11,##signatureN##); \
            }  \
        }   
    #endif
    // CHECK_AND_GET_NEIGHBOR_STATUS(neighbor_0, 0, 1)
    // CHECK_AND_GET_NEIGHBOR_STATUS(neighbor_1, 1, 1)
    // CHECK_AND_GET_NEIGHBOR_STATUS(neighbor_2, 2, 1)
    // CHECK_AND_GET_NEIGHBOR_STATUS(neighbor_3, 3, 1)
    if(signatureNow==1){\
                mask1 = (bit<32>)1 ;\
            }if(signatureNow == 2){\
                mask1 = (bit<32>)1 << 1;\
            }else if(signatureNow == 3){\
                mask1 = (bit<32>)1 << 2;\
            }else if(signatureNow == 4){\
                mask1 = (bit<32>)1 << 3;\
            }else if(signatureNow == 5){\
                mask1 = (bit<32>)1 << 4;\
            }else if(signatureNow == 6){\
                mask1 = (bit<32>)1 << 5;\
            }else if(signatureNow == 7){\
                mask1 = (bit<32>)1 << 6;\
            }else if(signatureNow == 8){\
                mask1 = (bit<32>)1 << 7;\
            }else if(signatureNow == 9){\
                mask1 = (bit<32>)1 << 8;\
            }else if(signatureNow == 10){\
                mask1 = (bit<32>)1 << 9;\
            }else if(signatureNow == 11){\
                mask1 = (bit<32>)1 << 10;\
            }\
                    if(reg_table_key_monitered==1){
                        store_neighbor_time_1_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==2){
                        store_neighbor_time_2_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==3){
                        store_neighbor_time_3_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==4){
                        store_neighbor_time_4_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==5){
                        store_neighbor_time_5_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==6){
                        store_neighbor_time_6_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==7){
                        store_neighbor_time_7_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==8){
                        store_neighbor_time_8_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==9){
                        store_neighbor_time_9_reg_action.execute(signatureNow);
                    }else if(reg_table_key_monitered==10){
                        store_neighbor_time_10_reg_action.execute(signatureNow);
                    }

    //n:neighbor's id; 
    #ifndef STORE_MONITERED_ALIVE_TIME
    #define STORE_MONITERED_ALIVE_TIME(n)\
        if(reg_table_key_monitered==##n##){\
            store_neighbor_time_##n##_reg_action.execute(signatureNow);\
        }
    #endif

                    STORE_MONITERED_ALIVE_TIME(1);
                    STORE_MONITERED_ALIVE_TIME(2);
                    STORE_MONITERED_ALIVE_TIME(3);
                    STORE_MONITERED_ALIVE_TIME(4);
                    STORE_MONITERED_ALIVE_TIME(5);
                    STORE_MONITERED_ALIVE_TIME(6);
                    STORE_MONITERED_ALIVE_TIME(7);
                    STORE_MONITERED_ALIVE_TIME(8);
                    STORE_MONITERED_ALIVE_TIME(9);
                    STORE_MONITERED_ALIVE_TIME(10);
                    STORE_MONITERED_ALIVE_TIME(11);


                if(next_Switch_state1==0){
                    if(next_switch_reg_key==1){
                        state_all=  get_neighbor_alive_state_string_11_reg_action.execute(1);
                        timeout_next_Switch1 =check_neighbor_time_1_reg_action.execute(11);
                    }else if(next_switch_reg_key==2){
                        timeout_next_Switch1 =check_neighbor_time_2_reg_action.execute(11);
                    }else if(next_switch_reg_key==3){
                        timeout_next_Switch1 =check_neighbor_time_3_reg_action.execute(11);
                    }else if(next_switch_reg_key==4){
                        timeout_next_Switch1 =check_neighbor_time_4_reg_action.execute(11);
                    }else if(next_switch_reg_key==5){
                        timeout_next_Switch1 =check_neighbor_time_5_reg_action.execute(11);
                    }else if(next_switch_reg_key==6){
                        timeout_next_Switch1 =check_neighbor_time_6_reg_action.execute(11);
                    }else if(next_switch_reg_key==7){
                        timeout_next_Switch1 =check_neighbor_time_7_reg_action.execute(11);
                    }else if(next_switch_reg_key==8){
                        timeout_next_Switch1 =check_neighbor_time_8_reg_action.execute(11);
                    }else if(next_switch_reg_key==9){
                        timeout_next_Switch1 =check_neighbor_time_9_reg_action.execute(11);
                    }else if(next_switch_reg_key==10){
                        timeout_next_Switch1 =check_neighbor_time_10_reg_action.execute(11);
                    }else if(next_switch_reg_key==11){
                        timeout_next_Switch1 =check_neighbor_time_11_reg_action.execute(11);
                    }
                }
    //     //the table of neighbor alive state
    // #ifndef GEN_NEIGHBOR_STATE_REGISTER
    // #define GEN_NEIGHBOR_STATE_REGISTER(n)\    
    // Register<register_state_t, reg_table_key_t>(node_num) neighbor_alive_reg_##n##; \
    // RegisterAction<register_state_t, reg_table_key_t, register_state_t>(neighbor_alive_reg_##n##) \
    // read_neighbor_alive_reg_##n##_action = {\
    //     void apply(inout register_state_t value, out register_state_t read_value){\
    //         read_value = value;     \
    //     }\
    // };\
    // RegisterAction<register_state_t, reg_table_key_t, register_state_t>(neighbor_alive_reg_##n##) \
    // store_neighbor_alive_reg_##n##_action = {   \
    //     void apply(inout register_state_t value){\
    //         if(store_state==0){\
    //             value=NOALIVE;\
    //         }else{\
    //             value=ALIVE;\
    //         }\
    //     }\
    // };
    // #endif

    // GEN_NEIGHBOR_STATE_REGISTER(1)
    // GEN_NEIGHBOR_STATE_REGISTER(2)
    // GEN_NEIGHBOR_STATE_REGISTER(3)
    // GEN_NEIGHBOR_STATE_REGISTER(4)
    // GEN_NEIGHBOR_STATE_REGISTER(5)
    // GEN_NEIGHBOR_STATE_REGISTER(6)
    // GEN_NEIGHBOR_STATE_REGISTER(7)
    // GEN_NEIGHBOR_STATE_REGISTER(8)
    // GEN_NEIGHBOR_STATE_REGISTER(9)
    // GEN_NEIGHBOR_STATE_REGISTER(10)
    // GEN_NEIGHBOR_STATE_REGISTER(11)

    // GEN_REGISTER_TIME(1)
    // GEN_REGISTER_TIME(2)
    // GEN_REGISTER_TIME(3)
    // GEN_REGISTER_TIME(4)
    GEN_REGISTER_TIME(5)
    GEN_REGISTER_TIME(6)
    GEN_REGISTER_TIME(7)
    GEN_REGISTER_TIME(8)
    // GEN_REGISTER_TIME(9)
    // GEN_REGISTER_TIME(10)
    GEN_REGISTER_TIME(11)


    // GEN_NEIGHBOR_STATE_STRING_REGISTER(1)
    // GEN_NEIGHBOR_STATE_STRING_REGISTER(2)
    // GEN_NEIGHBOR_STATE_STRING_REGISTER(3)
    // GEN_NEIGHBOR_STATE_STRING_REGISTER(4)
    GEN_NEIGHBOR_STATE_STRING_REGISTER(5)
    GEN_NEIGHBOR_STATE_STRING_REGISTER(6)
    GEN_NEIGHBOR_STATE_STRING_REGISTER(7)
    GEN_NEIGHBOR_STATE_STRING_REGISTER(8)
    // GEN_NEIGHBOR_STATE_STRING_REGISTER(9)
    // GEN_NEIGHBOR_STATE_STRING_REGISTER(10)
    GEN_NEIGHBOR_STATE_STRING_REGISTER(11)
