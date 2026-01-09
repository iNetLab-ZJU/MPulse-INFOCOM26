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
# from path import *
################### You can now use BFRT CLIENT ###########################



################### You can now use BFRT CLIENT ###########################

def setNeighborRegister(bfrt_info, interface, ip):
    target = gc.Target(device_id=0, pipe_id=0xffff)
    # Set the table as Asymmetric,which means different pipes
    mode = bfruntime_pb2.Mode.SINGLE


def setFlow(bfrt_info, interface, ip,pipeId):
    print("set flow")
    target = gc.Target(device_id=0, pipe_id=0xffff)
    # global global_grpc_comm_interface
    # bfrt_info = global_grpc_comm_interface.bfrt_info_get("tcp_fsm")
    pktgen_buffer = bfrt_info.table_get("tf2.pktgen.pkt_buffer")
    pktgen_port = bfrt_info.table_get("tf2.pktgen.port_cfg")
    pktgen_app = bfrt_info.table_get("tf2.pktgen.app_cfg")
    mgid_table = bfrt_info.table_get("$pre.mgid")
    node_table = bfrt_info.table_get("$pre.node")
    port_table = bfrt_info.table_get("$pre.port")
    ###
    pktgen_self_timeFlow = bfrt_info.table_get("pipe.SwitchIngress.timer_periodic")
    # port_down_table = bfrt_info.table_get("pipe.SwitchIngress.port_down_table")
    pktgen_heart_back = bfrt_info.table_get("pipe.SwitchIngress.heart_back")
    # receive_heartbeat = bfrt_info.table_get("pipe.SwitchIngress.receive_heartbeat")
    # neighbor_alive_reg = bfrt_info.table_get("pipe.SwitchIngress.neighbor_alive_reg")
    # receive_mulicast = bfrt_info.table_get("pipe.SwitchIngress.receive_mulicast")
    # change_port_table = bfrt_info.table_get("pipe.SwitchIngress.change_port_table")
    ###
    
    port_down_app_id=4
    outport = 0
    portdown_port =1
    src_port=69
    port_down_port=[69,197]

    ACK = 0
    REPLY = 1
    num_pipes = 2
    pipe_local_port=[68,196]
    app_id=2
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
    # mode2=bfruntime_pb2.Mode.ALL
    
    # neighbor_alive_reg.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode2)
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
    
    # p_count = len(neighborNode_list)
    # the more packets for consensus
    b_count = 1

    brids = [0, 1]

    neighborList_values = [
        # (0, 0, 0),
        # (0, 0, 0),
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
    
    signature = signature_list[0]
    # pipe_port=68
    
    
    # time.sleep(2)
    # for pipeId in range(num_pipes):
    # if pipeId==1:
    #     continue
    # batch=pipeId
    targetPipe = gc.Target(device_id=0, pipe_id=pipeId)
    signature, neighborNode_list, neighborNode_port,ip = switch_address_recognition(ip, pipeId)
    print(ip)
    print("###########pipe" + str(pipeId) + "###########")
    print(signature)
    print(neighborNode_list)
    print(neighborNode_port)
    # for i in range(12):
    #     AddRegisterData(bfrt_info,targetPipe,neighbor_alive_reg,i,1)
    pktgen_heart_back_key = pktgen_heart_back.make_key([gc.KeyTuple('hdr.heartbeat.heartbeat_type', ACK),
                                                        gc.KeyTuple('hdr.heartbeat.Monitored_switch', signature)])
    pktgen_heart_back_data = pktgen_heart_back.make_data([], 'SwitchIngress.heart_back_action')
    pktgen_heart_back.entry_add(targetPipe, [pktgen_heart_back_key], [pktgen_heart_back_data])

    n_count = len(neighborNode_list)
    # if signature==11 or signature==12:
    #     p_count = n_count+(signature-10)
    # else:
    #     p_count = n_count
    pipe_port=pipe_local_port[pipeId]
    pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', pipe_port)])
    pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
    pktgen_port.entry_mod(target, [pktgen_port_key], [pktgen_port_action_data])

    pkt_now=0
    for batch in range(b_count):
        for pkt_num in range(n_count):
            for i in range(2):
                neighborNodeList = neighbor_graph[neighborNode_list[pkt_num]][2*i:2*(i+1)]#0:2,2:4
                sum_N=0
                for j in range(len(neighborNodeList)):
                    sum_N=sum_N+neighborNodeList[j]*2**(j*4)
                print("*"*24)
                print(sum_N)
                if(sum_N==0):
                    continue
                # id=2*i+m
                pktgen_self_timeFlow_key = pktgen_self_timeFlow.make_key(
                    [gc.KeyTuple('hdr.timer.app_id', app_id), gc.KeyTuple('ig_intr_md.ingress_port', pipe_port),
                    gc.KeyTuple('hdr.timer.pipe_id', pipeId), gc.KeyTuple('hdr.timer.batch_id', batch),
                    gc.KeyTuple('hdr.timer.packet_id', pkt_now)])
                pktgen_self_timeFlow_data = pktgen_self_timeFlow.make_data(
                    [gc.DataTuple('port', neighborNode_port[neighborNode_list[pkt_num]]),
                    gc.DataTuple('Monitored_switch', neighborNode_list[pkt_num]),
                    gc.DataTuple('signature', signature),
                    gc.DataTuple('trans_neighbor_alive_list',sum_N)],'SwitchIngress.match_consensus')
                pktgen_self_timeFlow.entry_add(target, [pktgen_self_timeFlow_key], [pktgen_self_timeFlow_data])
                pkt_now+=1
    p_count=pkt_now
    print("*"*12+"p_count"+"*"*12)
    print(p_count)
    pktgen_app_key = pktgen_app.make_key([gc.KeyTuple('app_id', app_id)])
    pktgen_app_action_data = pktgen_app.make_data([gc.DataTuple('timer_nanosec', time_interval),
                                                gc.DataTuple('app_enable', bool_val=True),
                                                gc.DataTuple('pkt_len', packet_len),
                                                gc.DataTuple('pkt_buffer_offset', 0),
                                                gc.DataTuple('pipe_local_source_port', 68),
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
    pktgen_app.entry_mod(targetPipe, [pktgen_app_key], [pktgen_app_action_data])
def setFlow_1(bfrt_info, interface, ip,pipeId):
    print("set flow")
    target = gc.Target(device_id=0, pipe_id=0xffff)
    # global global_grpc_comm_interface
    # bfrt_info = global_grpc_comm_interface.bfrt_info_get("tcp_fsm")
    pktgen_buffer = bfrt_info.table_get("tf2.pktgen.pkt_buffer")
    pktgen_port = bfrt_info.table_get("tf2.pktgen.port_cfg")
    pktgen_app = bfrt_info.table_get("tf2.pktgen.app_cfg")
    mgid_table = bfrt_info.table_get("$pre.mgid")
    node_table = bfrt_info.table_get("$pre.node")
    port_table = bfrt_info.table_get("$pre.port")
    ###
    pktgen_self_timeFlow = bfrt_info.table_get("pipe_b.SwitchIngress.timer_periodic")
    pktgen_heart_back = bfrt_info.table_get("pipe_b.SwitchIngress.heart_back")
    port_down_table = bfrt_info.table_get("pipe_b.SwitchIngress.port_down_table")
    neighbor_num_table = bfrt_info.table_get("pipe_b.SwitchIngress.neighbor_num_table")
    # receive_heartbeat = bfrt_info.table_get("pipe.SwitchIngress.receive_heartbeat")
    neighbor_alive_reg = bfrt_info.table_get("pipe_b.SwitchIngress.neighbor_alive_reg")
    # receive_mulicast = bfrt_info.table_get("pipe.SwitchIngress.receive_mulicast")
    change_port_table = bfrt_info.table_get("pipe_b.SwitchIngress.change_port_table")
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
    neighborList_values = [
        # (0, 0, 0),
        # (0, 0, 0),
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

    # Set the table as Asymmetric,which means different pipes has diffrent values
    mode = bfruntime_pb2.Mode.SINGLE
    # receive_heartbeat.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    pktgen_heart_back.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    # neighbor_alive_reg.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    neighbor_num_table.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    # receive_mulicast.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    ###
    ###get all ids and neighbors, for multicast

    ## 实例化:认知到第几个交换机
    p_count_list = [0 for i in range(num_pipes)]
    neighborNode_list = []
    neighborNode_port_dict = {}
    # multi port

    index = 0
    signature, neighborNode_list, neighborNode_port,ip = switch_address_recognition(ip, pipeId)
    print(ip)
    print("###########pipe" + str(pipeId) + "###########")
    print(signature)
    print(neighborNode_list)
    print(neighborNode_port)
    p_count = len(neighborNode_list)
    b_count = 1
    ###
    # Set that has the list of bridge ids being used

    brids = [0, 1]
    # multicast，todo:test and set the drop ddl
    # brid_list = setMulticast(bfrt_info,target,mgid_table,node_table,brids,neighborNode_port_dict)
    for i in [68,196,197]:
        pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', i)])
        pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
        pktgen_port.entry_mod(target, [pktgen_port_key], [pktgen_port_action_data])

    for p in port_down_port:
        pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', p)])
        pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
        pktgen_port.entry_mod(target, [pktgen_port_key], [pktgen_port_action_data])
        ###

    # clearTable(target, pktgen_self_timeFlow)
    
    targetPipe = gc.Target(device_id=0, pipe_id=pipeId)
    for batch in range(b_count):
        for pkt_num in range(p_count):
            pktgen_self_timeFlow_key = pktgen_self_timeFlow.make_key(
                [gc.KeyTuple('hdr.timer.app_id', app_id), gc.KeyTuple('ig_intr_md.ingress_port', 196),
                 gc.KeyTuple('hdr.timer.pipe_id', 1), gc.KeyTuple('hdr.timer.batch_id', batch),
                 gc.KeyTuple('hdr.timer.packet_id', pkt_num)])
            pktgen_self_timeFlow_data = pktgen_self_timeFlow.make_data(
                [gc.DataTuple('port', neighborNode_port[neighborNode_list[pkt_num]]),
                 gc.DataTuple('Monitored_switch', neighborNode_list[pkt_num]),
                 gc.DataTuple('signature', signature)], 'SwitchIngress.match')
            pktgen_self_timeFlow.entry_add(target, [pktgen_self_timeFlow_key], [pktgen_self_timeFlow_data])
    # change_port_table.make_ke
    

    
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
    pktgen_app.entry_mod(targetPipe, [pktgen_app_key], [pktgen_app_action_data])
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
        targetPipe,
        [pktgen_app.make_key([gc.KeyTuple('app_id', port_down_app_id)])],
        [pktgen_app_action_down_data]
    )

    

    for i in range(len(neighbor_graph[signature])):
        next_port_v=neighbor_graph[signature][i]
        print(i,next_port_v)
        neighbor_num_table_key = neighbor_num_table.make_key([gc.KeyTuple('next_port',next_port_v)])                
        neighbor_num_table_data = neighbor_num_table.make_data([gc.DataTuple('neighborNum',i)],
                                        'SwitchIngress.neighbor_num_action')
        neighbor_num_table.entry_add(targetPipe,[neighbor_num_table_key],[neighbor_num_table_data])

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
                


down_time_record={11:[],12:[],1:[],3:[],2:[],
         4:[],5:[],7:[],6:[],
         8:[],9:[],10:[]}    

def check_digest(interface,learn_filter,pipe):
    while True:
        try:
            digestIter = interface.digest_get_iterator()
            print("resolve digest")
            print(pipe)
            for digest in digestIter:
                # print("have digest")
                data_list = learn_filter.make_data_list(digest)
                for data in data_list:
                    data_dict = data.to_dict()
                    # print(data_dict)
                    recv_signature = data_dict["signature"]
                    recv_port_0 = data_dict["port_0"]
                    recv_error_switch_0 = data_dict["error_switch_0"]
                    print(recv_port_0, recv_error_switch_0,recv_signature) if recv_error_switch_0 !=0 and recv_port_0== 1 else None
                    recv_port_1 = data_dict["port_1"]
                    recv_error_switch_1 = data_dict["error_switch_1"]
                    print(recv_port_1, recv_error_switch_1,recv_signature) if recv_error_switch_1!=0 and recv_port_1== 1 else None
                    # recv_port_2 = data_dict["port_2"]
                    # recv_error_switch_2 = data_dict["error_switch_2"]
                    # print(recv_port_2, recv_error_switch_2,recv_signature) if recv_error_switch_2!=0 and recv_port_2== 1 else None
                    # recv_port_3 = data_dict["port_3"]
                    # recv_error_switch_3 = data_dict["error_switch_3"]
                    # print(recv_port_3, recv_error_switch_3,recv_signature) if recv_error_switch_3!=0 and recv_port_3== 1 else None
                    # print(recv_port, recv_error_switch, recv_signature)
        except RuntimeError:
            pass

    
######main######
# ipList = ["192.168.8.111", "192.168.8.197", "192.168.8.194", "192.168.8.196", "192.168.8.199",
        #   "192.168.8.195"]
ipList = ["192.168.8.199"]
interface = {}
bfrt_info = {}
noheart_notification_list = {}

for x in ipList:
    print("***************" + x + "***************")
    bfrt_info[x], interface[x] = getBF(x)
    setNeighborRegister(bfrt_info[x], interface[x], x)
    
for x in ipList:
    setFlow(bfrt_info[x], interface[x], x,0)
    setFlow_1(bfrt_info[x], interface[x], x,1)

    learn_filter = bfrt_info[x].learn_get("pipe.SwitchIngressDeparser_c.digest")
    learn_filter.info.data_field_annotation_add("signature", "")
    learn_filter.info.data_field_annotation_add("port_1", "")
    learn_filter.info.data_field_annotation_add("error_switch_1", "")
    learn_filter.info.data_field_annotation_add("port_2", "")
    learn_filter.info.data_field_annotation_add("error_switch_2", "")
    learn_filter.info.data_field_annotation_add("port_3", "")
    learn_filter.info.data_field_annotation_add("error_switch_3", "")
    learn_filter.info.data_field_annotation_add("port_4", "")
    learn_filter.info.data_field_annotation_add("error_switch_4", "")
    check_digest_thread = threading.Thread(target=check_digest,args=(interface["192.168.8.199"],learn_filter,0,))
    check_digest_thread.start()



