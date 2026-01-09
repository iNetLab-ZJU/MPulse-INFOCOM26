#!/usr/bin/python3
import os
import sys
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

#use GRPC
SDE_INSTALL= os.environ['SDE_INSTALL']
SDE_PYTHON2= os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))

PYTHON3_VER= '{}.{}'.format(
	sys.version_info.major,
	sys.version_info.minor)
SDE_PYTHON3= os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
									'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
#grpc assistant function
#
# Connect to the BF Runtime Server
#
def getBF(ipAddr):
	for bfrt_client_id in range(10):
		try:
				interface = gc.ClientInterface(
					 grpc_addr = ipAddr+':50052',
					 client_id = bfrt_client_id,
					 device_id = 0,
					 num_tries = 1)
				print('Connected to BF Runtime Server as client', bfrt_client_id)
				break
		except:
				print(ipAddr,'Could not connect to BF Runtime server')
				quit
	#
	# Get the information about the running program
	#
	bfrt_info = interface.bfrt_info_get()
	print('The target runs the program ', bfrt_info.p4_name_get())
	#
	# Establish that you are using this program on the given connection
	#
	if bfrt_client_id == 0:
		interface.bind_pipeline_config(bfrt_info.p4_name_get())
	return bfrt_info,interface

def clearTable(target,table):
			table.entry_del(target)

class HeartBeat(Packet):
    name = "HeartBeat"
    fields_desc = [BitField("heartbeat_type", 0, 1),
                   BitField("signature", 0, 7),
                   BitField("Monitored_switch", 0, 7),
                   BitField("state", 0, 1),
                   BitField("protocol", 0x0800, 16)]
class neighborList(Packet):
    name = "neighborList"
    fields_desc = [BitField("neighbor", 0, 4),
                   BitField("state", 0, 3),
                   BitField("is_last", 0, 1)]
bind_layers(Ether, HeartBeat, type=0x5520)
bind_layers(Ether, neighborList)

