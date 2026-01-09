import json
import time

p4 = bfrt.codepipe
bit_length=32
def string_to_bits(string):
    # 将字符串转换为整数
    number = int(string)
    binary_str = format(number, '0{}b'.format(32))
    # 将整数转换为二进制字符串
    # binary_string = bin(number)[2:]
    return binary_str

#function
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    def _clear(table, verbose=False, batching=False):
        if verbose:
            print("Clearing table {:<40} ... ".
                  format(table['full_name']), end='', flush=True)
        try:    
            entries = table['node'].get(regex=True, print_ents=False)
            try:
                if batching:
                    bfrt.batch_begin()
                for entry in entries:
                    entry.remove()
            except Exception as e:
                print("Problem clearing table {}: {}".format(
                    table['name'], e.sts))
            finally:
                if batching:
                    bfrt.batch_end()
        except Exception as e:
            if e.sts == 6:
                if verbose:
                    print('(Empty) ', end='')
        finally:
            if verbose:
                print('Done')

        # Optionally reset the default action, but not all tables
        # have that
        try:
            table['node'].reset_default()
        except:
            pass
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members
    

    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)
            
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            _clear(table, verbose=verbose, batching=batching)

#clear_all()

#constants

reg_table_size = 65535



print("""
******************* PROGAMMING RESULTS *****************
""")
# fault 
bfrt.tf1.pktgen.port_cfg.mod(clear_port_down_enable=1,dev_port=188)
p4.pipe_b.SwitchIngress.port_down_time_reg.clear
bfrt.codepipe.pipe_a.SwitchIngress_c.down_time_id_reg.mod(REGISTER_INDEX=9,f1=0)
p4.pipe_a.SwitchIngress_c.down_time_reg.mod(REGISTER_INDEX=1,time_1=0,time_2=0)

bfrt.port.port.mod(DEV_PORT=188,PORT_ENABLE=0)
port_down_time_reg_text = p4.pipe_b.SwitchIngress.port_down_time_reg.get(REGISTER_INDEX=9,from_hw=1)
port_down_time_reg_time_1 = port_down_time_reg_text.data.get(b'SwitchIngress.port_down_time_reg.time_1')[0]
port_down_time_reg_time_2 = port_down_time_reg_text.data.get(b'SwitchIngress.port_down_time_reg.time_2')[0]
bits1 = string_to_bits(port_down_time_reg_time_1)
bits2 = string_to_bits(port_down_time_reg_time_2)
port_down_time = bits1 + bits2
start_time = int(port_down_time,2)
flag=0
while flag==0:
    port_detect_time_reg_text = p4.pipe_a.SwitchIngress_c.down_time_reg.get(REGISTER_INDEX=1,from_hw=1)
    port_detect_time_reg_time_1 = port_detect_time_reg_text.data.get(b'SwitchIngress_c.down_time_reg.time_1')[0]
    port_detect_time_reg_time_2 = port_detect_time_reg_text.data.get(b'SwitchIngress_c.down_time_reg.time_2')[0]
    if port_detect_time_reg_time_1!=0:
        flag=1
    Dbits1 = string_to_bits(port_detect_time_reg_time_1)
    Dbits2 = string_to_bits(port_detect_time_reg_time_2)
    port_detect_time = Dbits1 + Dbits2
    detect_time = int(port_detect_time,2)   
    print(str(start_time)+'  '+str(detect_time)+'  '+str(detect_time-start_time)+'\n')
    with open('/root/pktgen/zuhe/down_time_detect/detectTime.txt', 'a') as time_file :
            time_file.writelines([str(start_time)+'  '+str(detect_time)+'  '+str(detect_time-start_time)+'\n'])   
bfrt.port.port.mod(DEV_PORT=188,PORT_ENABLE=True) 
bfrt.tf1.pktgen.port_cfg.mod(clear_port_down_enable=1,dev_port=188)
#p4.pipe_b.SwitchIngress.port_down_time_reg.mod(REGISTER_INDEX=9,time_1=0,time_2=0)
p4.pipe_b.SwitchIngress.port_down_time_reg.clear
bfrt.codepipe.pipe_a.SwitchIngress_c.down_time_id_reg.mod(REGISTER_INDEX=9,f1=0)
bfrt.complete_operations()
