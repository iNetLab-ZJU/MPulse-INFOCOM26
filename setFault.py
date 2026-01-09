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


################### You can now use BFRT CLIENT ###########################




################### You can now use BFRT CLIENT ###########################


def setFlow(bfrt_info, interface, ip):
    target = gc.Target(device_id=0, pipe_id=0xffff)
    # global global_grpc_comm_interface
    # bfrt_info = global_grpc_comm_interface.bfrt_info_get("tcp_fsm")
    pktgen_buffer = bfrt_info.table_get("tf1.pktgen.pkt_buffer")
    pktgen_port = bfrt_info.table_get("tf1.pktgen.port_cfg")
    pktgen_app = bfrt_info.table_get("tf1.pktgen.app_cfg")
    mgid_table = bfrt_info.table_get("$pre.mgid")
    node_table = bfrt_info.table_get("$pre.node")
    port_table = bfrt_info.table_get("$pre.port")
    ###
    pktgen_self_timeFlow = bfrt_info.table_get("pipe.SwitchIngress.timer_periodic")
    pktgen_heart_back = bfrt_info.table_get("pipe.SwitchIngress.heart_back")
    receive_heartbeat = bfrt_info.table_get("pipe.SwitchIngress.receive_heartbeat")
    neighbor_alive_reg = bfrt_info.table_get("pipe.SwitchIngress.neighbor_alive_reg")

    receive_mulicast = bfrt_info.table_get("pipe.SwitchIngress.receive_mulicast")
    ###

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
    time_interval = 40000000
    # time_interval = 5000
    ttl_query_length = 2 * time_interval
    ttl_set = 2 * time_interval
    max_ttl = 10000
    min_ttl = 1000

    # Set the table as Asymmetric,which means different pipes
    mode = bfruntime_pb2.Mode.SINGLE
    receive_heartbeat.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    pktgen_heart_back.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    neighbor_alive_reg.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)

    receive_mulicast.attribute_entry_scope_set(target, predefined_pipe_scope=True, predefined_pipe_scope_val=mode)
    ###
    ###get all ids and neighbors, for multicast

    ## 实例化:认知到第几个交换机
    p_count_list = [0 for i in range(num_pipes)]
    signature_list = []
    neighborNode_list = []
    neighborNode_port_dict = {}
    # multi port
    for i in range(num_pipes):
        signature, neighborNode_list1, neighborNode_port1 = switch_address_recognition(ip, i)
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
    # multicast，todo:test and set the drop ddl
    # Dict to hold interface id for each port
    port_to_ifid = {}
    # Dict to hold multicast mgid for each bridge id
    brid_to_mgid = {}
    # Dict to hold multicast L1 id for each bridge id
    brid_to_l1 = {}
    # Set that has the list of bridge ids being used
    brids = [0, 1]

    for brid in brids:
        brid_to_mgid[brid] = (brid & 0xFFFF)

        try:
            mgid_table.entry_add(
                target,
                [mgid_table.make_key(
                    [gc.KeyTuple('$MGID', (brid & 0xFFFF))])])
        except:
            mgid_table.entry_mod(
                target,
                [mgid_table.make_key(
                    [gc.KeyTuple('$MGID', (brid & 0xFFFF))])])

    l1_id = 1

    for brid in brids:
        rid = (~brid) & 0xFFFF  # rid is 16 bits and make sure it is different from brid
        brid_to_l1[brid] = l1_id
        try:
            node_table.entry_add(
                target,
                [node_table.make_key([
                    gc.KeyTuple('$MULTICAST_NODE_ID', l1_id)])],
                [node_table.make_data([
                    gc.DataTuple('$MULTICAST_RID', rid),
                    gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=[]),
                    gc.DataTuple('$DEV_PORT', int_arr_val=[])])]
            )

        except:
            node_table.entry_mod(
                target,
                [node_table.make_key([
                    gc.KeyTuple('$MULTICAST_NODE_ID', l1_id)])],
                [node_table.make_data([
                    gc.DataTuple('$MULTICAST_RID', rid),
                    gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=[]),
                    gc.DataTuple('$DEV_PORT', int_arr_val=[])])]
            )

        l1_id = l1_id + 1
    brid_list = list(brids)
    # brid_list = [0,1]
    ###
    # Add L2 nodes to the L1s
    ports_in_tree = {}
    # Add all ports to the first
    l2_node_ports = []
    l2_node_lags = []
    for m in range(num_pipes):
        l2_node_ports = list(neighborNode_port_dict[m].values())
        ports_in_tree[brid_list[m]] = sorted(l2_node_ports)
        node_table.entry_mod(
            target,
            [node_table.make_key([gc.KeyTuple('$MULTICAST_NODE_ID', brid_to_l1[brid_list[m]])])],
            [node_table.make_data([
                gc.DataTuple('$MULTICAST_RID', ((~brid_list[m]) & 0xFFFF)),
                gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=l2_node_lags),
                gc.DataTuple('$DEV_PORT', int_arr_val=l2_node_ports)])])
        mgid_table.entry_mod(
            target,
            [mgid_table.make_key([gc.KeyTuple('$MGID', brid_to_mgid[brid_list[m]])])],
            [mgid_table.make_data([
                gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=[brid_to_l1[brid_list[m]]]),
                gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[0]),
                gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[0])])])
        l2_node_ports.clear()

    pktgen_port_key = pktgen_port.make_key([gc.KeyTuple('dev_port', pipe_local_port)])
    pktgen_port_action_data = pktgen_port.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])
    pktgen_port.entry_mod(target, [pktgen_port_key], [pktgen_port_action_data])
    resp = pktgen_port.entry_get(
        target,
        [pktgen_port.make_key([gc.KeyTuple('dev_port', pipe_local_port)])],
        {"from_hw": False})
    data_dict = next(resp)[0].to_dict()
    print(data_dict)
    ###
    ## Configuring pktgen buffer
    p = Ether(src=src_mac, dst=dst_mac) / HeartBeat() / IP(src="42.42.42.42", dst="1.1.1.1") / TCP(dport=443,
                                                                                                   sport=sport_value)
    p.show()
    packet_len = len(p)
    offset = 0
    pktgen_pkt_buf_key = pktgen_buffer.make_key(
        [gc.KeyTuple('pkt_buffer_offset', offset), gc.KeyTuple('pkt_buffer_size', packet_len)])
    pktgen_pkt_buf_action_data = pktgen_buffer.make_data([gc.DataTuple('buffer', bytearray(bytes(p)))])
    pktgen_buffer.entry_mod(target, [pktgen_pkt_buf_key], [pktgen_pkt_buf_action_data])
    index = 0
    signature = signature_list[0]

    clearTable(target, pktgen_self_timeFlow)

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
    # Read the app configuration back
    resp = pktgen_app.entry_get(
        target,
        [pktgen_app.make_key([gc.KeyTuple('app_id', app_id)])],
        {"from_hw": False},
        pktgen_app.make_data([gc.DataTuple('timer_nanosec'),
                              gc.DataTuple('app_enable'),
                              gc.DataTuple('pkt_len'),
                              gc.DataTuple('pkt_buffer_offset'),
                              gc.DataTuple('pipe_local_source_port'),
                              gc.DataTuple('increment_source_port'),
                              gc.DataTuple('batch_count_cfg'),
                              gc.DataTuple('packets_per_batch_cfg'),
                              gc.DataTuple('ibg'),
                              gc.DataTuple('ibg_jitter'),
                              gc.DataTuple('ipg'),
                              gc.DataTuple('ipg_jitter')],
                             'trigger_timer_periodic', get=True))
    data_dict = next(resp)[0].to_dict()
    print(data_dict)
    ######

    time.sleep(2)
    for i in range(num_pipes):
        targetPipe = gc.Target(device_id=0, pipe_id=i)
        signature, neighborNode_list, neighborNode_port = switch_address_recognition(ip, i)
        print(ip)
        print("###########pipe" + str(i) + "###########")
        print(signature)
        print(neighborNode_list)
        print(neighborNode_port)

        clearTable(targetPipe, pktgen_heart_back)
        pktgen_heart_back_key = pktgen_heart_back.make_key([gc.KeyTuple('hdr.heartbeat.heartbeat_type', ACK),
                                                            gc.KeyTuple('hdr.heartbeat.Monitored_switch', signature)])
        pktgen_heart_back_data = pktgen_heart_back.make_data([], 'SwitchIngress.heart_back_action')
        pktgen_heart_back.entry_add(targetPipe, [pktgen_heart_back_key], [pktgen_heart_back_data])
        resp = pktgen_heart_back.entry_get(
            targetPipe,
            [pktgen_heart_back.make_key([gc.KeyTuple('hdr.heartbeat.heartbeat_type', ACK),
                                         gc.KeyTuple('hdr.heartbeat.Monitored_switch', signature)])],
            {"from_hw": True})
        data_dict = next(resp)[0].to_dict()
        print(data_dict)

        clearTable(targetPipe, receive_mulicast)
        receive_mulicast_key = receive_mulicast.make_key([gc.KeyTuple('hdr.heartbeat.heartbeat_type', REPLY)])
        receive_mulicast_data = receive_mulicast.make_data([], 'SwitchIngress.receive_mulicast_action')
        receive_mulicast.entry_add(targetPipe, [receive_mulicast_key], [receive_mulicast_data])

        n_count = len(neighborNode_list)
        clearTable(targetPipe, receive_heartbeat)
        for neighbor in range(n_count):
            receive_heartbeat.entry_add(
                targetPipe,
                [receive_heartbeat.make_key([gc.KeyTuple('hdr.heartbeat.heartbeat_type', REPLY),
                                             gc.KeyTuple('hdr.heartbeat.Monitored_switch', neighborNode_list[neighbor]),
                                             gc.KeyTuple('hdr.heartbeat.signature', signature)])],
                [receive_heartbeat.make_data([gc.DataTuple('mcast_grp_id', brid_list[i])],
                                             'SwitchIngress.receive_heartbeat_action')]
            )


def GetRegisterData(bfrt_info, target, register, register_idx):
    resp = register.entry_get(
        target,
        [register.make_key([gc.KeyTuple('$REGISTER_INDEX', register_idx)])])
    data, _ = next(resp)
    data_dict = data.to_dict()
    return data_dict["SwitchIngress.neighbor_alive_reg.f1"]


######main######
ipList = ["192.168.123.111", "192.168.123.197", "192.168.123.194", "192.168.123.196", "192.168.123.103",
          "192.168.123.195"]
# ipList = ["192.168.123.195"]
interface = {}
bfrt_info = {}
noheart_notification_list = {}

for x in ipList:
    print("***************" + x + "***************")
    bfrt_info[x], interface[x] = getBF(x)
    setFlow(bfrt_info[x], interface[x], x)

error = {}
key = {}
sta = {}
num = {}
error_mon = {}
t = {}
lock = threading.Lock()
print("\n---------------------------------Start testing------------------------------")
# while True:
#     for ip in ipList:
#         for pipe in range(2):
#             ip_last_three = '.'.join(ip.split('.')[3:])
#             switch=ip_last_three+str(pipe)
#             sta[switch],key[switch],error_mon[switch],error[switch],num[switch]= DetectReg(bfrt_info[ip], interface[ip], ip, pipe)
#     # print(sta)
#     # print(key)
#     # print(error)
#     # print(num)
#     time.sleep(1)
while True:
    Switch = []
    for ip in ipList:
        for pipe in range(2):
            ip_last_three = '.'.join(ip.split('.')[3:])
            switch = ip_last_three + str(pipe)
            Switch.append(switch)
            t[switch] = threading.Thread(target=DetectReg, args=(bfrt_info[ip], interface[ip], ip, pipe))
            t[switch].start()
    # for switch in Switch:
    #     t[switch].join()

    time.sleep(1)




