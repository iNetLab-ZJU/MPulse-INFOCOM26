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
            # recv_port_2 = data_dict["port_2"]
            # recv_error_switch_2 = data_dict["error_switch_2"]
            # print(recv_port_2, recv_error_switch_2,recv_signature) if recv_error_switch_2!=0 else None
            # recv_port_3 = data_dict["port_3"]
            # recv_error_switch_3 = data_dict["error_switch_3"]
            # print(recv_port_3, recv_error_switch_3,recv_signature) if recv_error_switch_3!=0 else None
            # print(recv_port, recv_error_switch, recv_signature)
        except RuntimeError:
            pass

    
######main######
# ipList = ["192.168.123.111", "192.168.123.197", "192.168.123.194", "192.168.123.196", "192.168.123.103",
        #   "192.168.123.195"]
ipList = ["192.168.123.194","192.168.123.196"]
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

    check_digest_thread = threading.Thread(target=check_digest,args=(interface[x],learn_filter,x,))
    check_digest_thread.start()




