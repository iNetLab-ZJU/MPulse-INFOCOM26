#!/usr/bin/python3

import os
import sys
import pdb
import glob
import time
import socket
import fcntl
import struct
import queue
import threading
from scapy import *
from scapy.layers.inet import Ether, IP, TCP
from scapy.all import (
    Ether,
    IntField,
    Packet,
    BitField,
    StrFixedLenField,
    XByteField,
    bind_layers,
    srp1
)

from utils_python.utils_p4 import *
from utils_python.utils import *
from path import *
################### You can now use BFRT CLIENT ###########################
flowRoute={
    # ingress_port,port,switch_id
    # ["192.168.123.194","192.168.123.196","192.168.123.111", "192.168.123.197","192.168.123.195"]
    # 1: [[140,156,6]],
    # 5: [[156,148,2],[140,156,10]],
    # 6: [[140,156,10],[156,148,2]],
    #     9: [[140,132,5]],
    # 10:[[12,4,5]],
    # 2: [[132,148,0]],
    #     7:[[20,20,4]],
    #     8: [[28,20,4]],
    #     4: [[28,20,0]]
    1: [[140,156,6]],
    5: [[140,148,2]],
    6: [[140,148,2]],
    2: [[132,148,0]]
}

backRoute={
    # ["192.168.123.194","192.168.123.196","192.168.123.111", "192.168.123.197","192.168.123.195"]
    1: [[6 ,132 ]]
    # 4: [[0    ]]
}


################### You can now use BFRT CLIENT ###########################

def setNeighborRegister(bfrt_info, interface, ip):
    print("clear all tables")
    interface.clear_all_tables()
    print("clear all tables_over")
    # target = gc.Target(device_id=0, pipe_id=0xffff)
    # Set the table as Asymmetric,which means different pipes
    # mode = bfruntime_pb2.Mode.SINGLE
    # neighbor_id_reg = bfrt_info.table_get("pipe.SwitchIngress.neighbor_id_reg")
    # for i in neighbor_graph:
    #     neighborNode_list = neighbor_graph[i]
    #     sum_N=0
    #     for j in range(len(neighborNode_list)):
    #         sum_N=sum_N+neighborNode_list[j]*2**(j*4)
    #     print("*"*24)
    #     print(sum_N)
    #     AddRegisterData(bfrt_info,target,neighbor_id_reg,i,sum_N)

def setFlow(bfrt_info, interface, ip):
    print("set flow")
    target = gc.Target(device_id=0, pipe_id=0xffff)
    # global global_grpc_comm_interface
    # bfrt_info = global_grpc_comm_interface.bfrt_info_get("tcp_fsm")
    pktgen_buffer = bfrt_info.table_get("tf1.pktgen.pkt_buffer")
    pktgen_port = bfrt_info.table_get("tf1.pktgen.port_cfg")
    pktgen_app = bfrt_info.table_get("tf1.pktgen.app_cfg")
    # mgid_table = bfrt_info.table_get("$pre.mgid")
    # node_table = bfrt_info.table_get("$pre.node")
    # port_table = bfrt_info.table_get("$pre.port")
    ###
    pktgen_self_timeFlow = bfrt_info.table_get("pipe.SwitchIngress.timer_periodic")
    pktgen_heart_back = bfrt_info.table_get("pipe.SwitchIngress.heart_back")
    port_down_table = bfrt_info.table_get("pipe.SwitchIngress.port_down_table")
    forward_table= bfrt_info.table_get("pipe.SwitchIngress.port_down_table")
    # neighbor_num_table = bfrt_info.table_get("pipe.SwitchIngress.neighbor_num_table")
    # receive_heartbeat = bfrt_info.table_get("pipe.SwitchIngress.receive_heartbeat")
    # neighbor_alive_reg = bfrt_info.table_get("pipe.SwitchIngress.neighbor_alive_reg")
    # receive_mulicast = bfrt_info.table_get("pipe.SwitchIngress.receive_mulicast")
    change_port_table = bfrt_info.table_get("pipe.SwitchIngress.change_port_table")
    ###

    port_down_app_id=4
    outport = 0
    portdown_port =1
    src_port=69
    port_down_port=[69,197]

    ACK = 0
    REPLY = 1
    num_pipes = 2
    pipe_local_port = 68
    app_id = 2
    ibg = 10
    ibg_jitter = 0
    ipg = 50
    ipg_jitter = 10
    sport_value = 1234
    src_mac = "00:AA:BB:CC:DD:EE"
    dst_mac = "00:EE:DD:CC:BB:AA"
    # Set Idle Table attributes
    time_interval = 400000000
    # time_interval = 5000
    ttl_query_length = 2 * time_interval
    ttl_set = 2 * time_interval
    max_ttl = 10000
    min_ttl = 1000


    # Set the table as Asymmetric,which means different pipes has diffrent values
    mode = bfruntime_pb2.Mode.SINGLE
    # receive_heartbeat.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    pktgen_heart_back.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    
    # neighbor_alive_reg.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    # neighbor_num_table.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    # receive_mulicast.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    ###
    ###get all ids and neighbors, for multicast

    ## 实例化:认知到第几个交换机
    p_count_list = [0 for i in range(num_pipes)]
    signature_list = []
    neighborNode_list = []
    neighborNode_port_dict = {}
    # multi port
    for i in range(num_pipes):
        signature, neighborNode_list1, neighborNode_port1,ip = switch_address_recognition(ip, i)
        print(ip)
        signature_list.append(signature)
        p_count_list[i] = len(neighborNode_list1)
        neighborNode_list = neighborNode_list + neighborNode_list1
        # neighborNode_port.update(neighborNode_port1)
        neighborNode_port_dict[i] = neighborNode_port1
    print(neighborNode_list)
    print(neighborNode_port_dict)
    
    p_count = len(neighborNode_list)
    b_count = 1
    ###
    # Set that has the list of bridge ids being used

    brids = [0, 1]
    # multicast，todo:test and set the drop ddl
    # brid_list = setMulticast(bfrt_info,target,mgid_table,node_table,brids,neighborNode_port_dict)

    pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', pipe_local_port)])
    pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
    pktgen_port.entry_mod(target, [pktgen_port_key], [pktgen_port_action_data])
    resp = pktgen_port.entry_get(
        target,
        [pktgen_port.make_key([gc.KeyTuple('dev_port', pipe_local_port)])],
        {"from_hw": False})
    data_dict = next(resp)[0].to_dict()
    print("pktgen_port")
    print(data_dict)

    for p in port_down_port:
        pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', p)])
        pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
        pktgen_port.entry_mod(target, [pktgen_port_key], [pktgen_port_action_data])
        ###
    ## Configuring pktgen buffer
    p = Ether(src=src_mac, dst=dst_mac) / HeartBeat() 
    neighborList_values = [
        (0, 0, 0),
        (0, 0, 0),
        (0, 0, 0),
        (0, 0, 1)
    ]
    # 使用for循环，逐个添加HeartBeat数据包到Ethernet数据帧中
    pkt = Ether(src=src_mac, dst=dst_mac) / HeartBeat()
    for neighbor, state, is_last in neighborList_values:
        neighborlist = neighborList(neighbor=neighbor, state=state,is_last=is_last)
        pkt = pkt / neighborlist
    

    p = pkt /IP(src="42.42.42.42", dst="1.1.1.1") / TCP(dport=443,sport=1234)  
    p.show()

    packet_len = len(p)
    offset = 0
    pktgen_pkt_buf_key = pktgen_buffer.make_key(
        [gc.KeyTuple('pkt_buffer_offset', offset), gc.KeyTuple('pkt_buffer_size', packet_len)])
    pktgen_pkt_buf_action_data = pktgen_buffer.make_data([gc.DataTuple('buffer', bytearray(bytes(p)))])
    pktgen_buffer.entry_mod(target, [pktgen_pkt_buf_key], [pktgen_pkt_buf_action_data])
    index = 0
    signature = signature_list[0]

    # clearTable(target, pktgen_self_timeFlow)

    for batch in range(b_count):
        for pkt_num in range(p_count):
            if pkt_num == sum(p_count_list[:index + 1]):
                index = index + 1
            print(signature_list[index])
            pktgen_self_timeFlow_key = pktgen_self_timeFlow.make_key(
                [gc.KeyTuple('hdr.timer.app_id', app_id), gc.KeyTuple('ig_intr_md.ingress_port', pipe_local_port),
                 gc.KeyTuple('hdr.timer.pipe_id', 0), gc.KeyTuple('hdr.timer.batch_id', batch),
                 gc.KeyTuple('hdr.timer.packet_id', pkt_num)])
            pktgen_self_timeFlow_data = pktgen_self_timeFlow.make_data(
                [gc.DataTuple('port', neighborNode_port_dict[index][neighborNode_list[pkt_num]]),
                 gc.DataTuple('Monitored_switch', neighborNode_list[pkt_num]),
                 gc.DataTuple('signature', signature_list[index])], 'SwitchIngress.match')
            pktgen_self_timeFlow.entry_add(target, [pktgen_self_timeFlow_key], [pktgen_self_timeFlow_data])

    

    
    ## Configuring pktgen app
    pktgen_app_key = pktgen_app.make_key([gc.KeyTuple('app_id', app_id)])
    pktgen_app_action_data = pktgen_app.make_data([gc.DataTuple('timer_nanosec', time_interval),
                                                   gc.DataTuple('app_enable', bool_val=True),
                                                   gc.DataTuple('pkt_len', packet_len),
                                                   gc.DataTuple('pkt_buffer_offset', 0),
                                                   gc.DataTuple('pipe_local_source_port', pipe_local_port),
                                                   gc.DataTuple('increment_source_port', bool_val=False),
                                                   gc.DataTuple('batch_count_cfg', b_count - 1),
                                                   gc.DataTuple('packets_per_batch_cfg', p_count - 1),
                                                   gc.DataTuple('ibg', ibg),
                                                   gc.DataTuple('ibg_jitter', ibg_jitter),
                                                   gc.DataTuple('ipg', ipg),
                                                   gc.DataTuple('ipg_jitter', ipg_jitter),
                                                   gc.DataTuple('batch_counter', 0),
                                                   gc.DataTuple('pkt_counter', 0),
                                                   gc.DataTuple('trigger_counter', 0)],
                                                  'trigger_timer_periodic')
    pktgen_app.entry_mod(target, [pktgen_app_key], [pktgen_app_action_data])
    ######
    pktgen_app_action_down_data = pktgen_app.make_data([gc.DataTuple('app_enable', bool_val=True),
                                                        gc.DataTuple('pkt_len', packet_len),
                                                        gc.DataTuple('pkt_buffer_offset', 0),
                                                        gc.DataTuple('pipe_local_source_port', port_down_port[0]),
                                                        gc.DataTuple('increment_source_port', bool_val=False),
                                                        gc.DataTuple('batch_count_cfg', 0),
                                                        gc.DataTuple('packets_per_batch_cfg', 0),
                                                        gc.DataTuple('batch_counter', 0),
                                                        gc.DataTuple('pkt_counter', 0),
                                                        gc.DataTuple('trigger_counter', 0)],
                                                        'trigger_port_down')
    pktgen_app.entry_mod(
        target,
        [pktgen_app.make_key([gc.KeyTuple('app_id', port_down_app_id)])],
        [pktgen_app_action_down_data]
    )
    for switchNum in flowRoute:
        if switchNum == signature:
            for route in flowRoute[switchNum]:
                ingress_port=route[0]
                port=route[1]
                nextSwitchId=route[2]
                forward_table.entry_add(target,
                        [forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port',ingress_port)])],
                        [forward_table.make_data([gc.DataTuple('port', port),gc.DataTuple('nextSwitchId', nextSwitchId)],'Ingress.l3_switch')]
                        )
    for change_port in backRoute:
        if switchNum == signature:
            for backroute in backRoute[change_port]:
                next_Switch = backroute[0]
                back_port = backroute[1]
                change_port_table_key = change_port_table.make_key([gc.KeyTuple('next_Switch',next_Switch)])                
                change_port_table_data = change_port_table.make_data([gc.DataTuple('back_port',back_port)],
                                            'SwitchIngress.change_port')
                change_port_table.entry_add(targetPipe,[change_port_table_key],[change_port_table_data])



    # time.sleep(2)
    for pipeId in range(num_pipes):
        targetPipe = gc.Target(device_id=0, pipe_id=pipeId)
        signature, neighborNode_list, neighborNode_port,ip = switch_address_recognition(ip, pipeId)
        print(ip)
        print("###########pipe" + str(pipeId) + "###########")
        print(signature)
        print(neighborNode_list)
        print(neighborNode_port)


        # clearTable(targetPipe, pktgen_heart_back)
        pktgen_heart_back_key = pktgen_heart_back.make_key([gc.KeyTuple('hdr.heartbeat.heartbeat_type', ACK),
                                                            gc.KeyTuple('hdr.heartbeat.Monitored_switch', signature)])
        pktgen_heart_back_data = pktgen_heart_back.make_data([], 'SwitchIngress.heart_back_action')
        pktgen_heart_back.entry_add(targetPipe, [pktgen_heart_back_key], [pktgen_heart_back_data])
        
        # n_count = len(neighborNode_list)
        pd_port=port_down_port[0]
        ports_to_flap=neighborNode_port.values()
        for port_num in neighborNode_port:
            port_down_table_key = port_down_table.make_key(
                        [gc.KeyTuple('hdr.port_down.app_id', port_down_app_id), gc.KeyTuple('ig_intr_md.ingress_port', 197),
                        gc.KeyTuple('hdr.port_down.pipe_id', pipeId), 
                        gc.KeyTuple('hdr.port_down.port_num', neighborNode_port[port_num]),
                        gc.KeyTuple('hdr.port_down.packet_id', 0)])
            port_down_table_data = port_down_table.make_data(
                [gc.DataTuple('port', neighborNode_port[12]),
                gc.DataTuple('Monitored_switch', signature),
                gc.DataTuple('signature', signature)], 'SwitchIngress.match_down')
            port_down_table.entry_add(target, [port_down_table_key], [port_down_table_data])
        for port in ports_to_flap:
                pktgen_port.entry_mod(
                    target,
                    [pktgen_port.make_key([gc.KeyTuple('dev_port', port)])],
                    [pktgen_port.make_data([gc.DataTuple('clear_port_down_enable', bool_val=True)])])           

    

def check_digest(interface,learn_filter,ip):
    while True:
        try:
            digest = interface.digest_get()
            # print("have digest")
            print("resolve digest")
            print(ip)
            data_list = learn_filter.make_data_list(digest)
            data_dict = data_list[0].to_dict()
            recv_signature = data_dict["signature"]
            recv_port_0 = data_dict["port_0"]
            recv_error_switch_0 = data_dict["error_switch_0"]
            print(recv_port_0, recv_error_switch_0,recv_signature) if recv_error_switch_0 !=0 else None
            recv_port_1 = data_dict["port_1"]
            recv_error_switch_1 = data_dict["error_switch_1"]
            print(recv_port_1, recv_error_switch_1,recv_signature) if recv_error_switch_1!=0 else None
            recv_port_2 = data_dict["port_2"]
            recv_error_switch_2 = data_dict["error_switch_2"]
            print(recv_port_2, recv_error_switch_2,recv_signature) if recv_error_switch_2!=0 else None
            recv_port_3 = data_dict["port_3"]
            recv_error_switch_3 = data_dict["error_switch_3"]
            print(recv_port_3, recv_error_switch_3,recv_signature) if recv_error_switch_3!=0 else None
            # print(recv_port, recv_error_switch, recv_signature)
        except RuntimeError:
            pass

    
######main######
# ipList = ["192.168.123.111", "192.168.123.197", "192.168.123.194", "192.168.123.196", "192.168.123.103",
        #   "192.168.123.195"]
ipList = ["192.168.123.195"]
interface = {}
bfrt_info = {}
noheart_notification_list = {}

for x in ipList:
    print("***************" + x + "***************")
    bfrt_info[x], interface[x] = getBF(x)
    setNeighborRegister(bfrt_info[x], interface[x], x)
    
for x in ipList:
    setFlow(bfrt_info[x], interface[x], x)

    learn_filter = bfrt_info[x].learn_get("digest")
    learn_filter.info.data_field_annotation_add("signature", "")

    learn_filter.info.data_field_annotation_add("port_0", "")
    learn_filter.info.data_field_annotation_add("error_switch_0", "")
    learn_filter.info.data_field_annotation_add("port_1", "")
    learn_filter.info.data_field_annotation_add("error_switch_1", "")
    learn_filter.info.data_field_annotation_add("port_2", "")
    learn_filter.info.data_field_annotation_add("error_switch_2", "")
    learn_filter.info.data_field_annotation_add("port_3", "")
    learn_filter.info.data_field_annotation_add("error_switch_3", "")

    check_digest_thread = threading.Thread(target=check_digest,args=(interface[x],learn_filter,x,))
    check_digest_thread.start()




