
import socket
import fcntl
import struct
from utils_python.utils_p4 import *

neighbor_graph = {11:[1,2,3,4,5,6,7,8,9,10],1:[5,6,11],3:[7,8,11],2:[5,6,11],
		 4:[7,8,11],5:[1,2,9,10,11],7:[3,4,9,10,11],6:[1,2,9,10,11],
		 8:[3,4,9,10,11],9:[5,6,7,8,11],10:[5,6,7,8,11]}
neighbor_graph_list = {11:{1:60,2:52,3:44,4:36,5:28,6:20,7:12,8:4,9:0,10:8},
				  1:{5:132,6:156,11:164},
				  3:{7:4,8:28,11:36},
				  2:{5:132,6:156,11:164},
		 		  4:{7:4,8:28,11:36},
				  5:{1:140,2:148,9:132,10:156,11:164},
				  7:{3:12,4:20,9:4,10:28,11:36},
				  6:{1:140,2:148,9:132,10:156,11:164},
				  8:{3:12,4:20,9:4,10:28,11:36},
				  9:{5:132,6:140,7:148,8:156,11:164},
				  10:{5:4,6:12,7:20,8:28,11:36}}
# signature:{target:trans_port_list}
# neighbor_graph = {11:[],12:[1,5,3,7,9],1:[5],3:[7],2:[5,6],
# 		 4:[7,8],5:[1,9],7:[3,9],6:[1,2,9,10],
# 		 8:[3,4,9,10],9:[5,7],10:[5,6,7,8]}

# trans_node={11:{"port":148,121:[5,7],122:[9,10]},12:{"port":36,111:[1,2],112:[3,4],113:[6,8]}}

                                                                                                                                                                                                                            
# def switch103_1():
# 	signature = 12
# 	ip = "192.168.123.103"
# 	neighborNode_list = [1,2,3,4,5,6,7,8,9,10]
# 	neighborNode_port = {5:172,7:164,12:188}
# 	return signature,neighborNode_list,neighborNode_port,ip

def switch103_2():
	signature = 11
	ip = "192.168.123.103"
	neighborNode_list = [1,2,3,4,5,6,7,8,9,10]
	neighborNode_port = {1:60,2:52,3:44,4:36,5:28,6:20,7:12,8:4,9:0,10:8}
	
	# neighborNode_list = [1,2,3,4,6,8,5,7,9,10]
	# neighborNode_port = {1:0,2:60,3:8,4:52,6:16,8:24,5:32,7:40,9:48,10:56}
	return signature,neighborNode_list,neighborNode_port,ip

def switch196_1():
	signature = 1
	ip = "192.168.123.196"
	neighborNode_list = [5,6,11]
	neighborNode_port = {5:132,6:156,11:164}
	# neighborNode_list = [5,12]
	# neighborNode_port = {5:132,12:164}
	return signature,neighborNode_list,neighborNode_port,ip

def switch196_2():
	signature = 3
	ip = "192.168.123.196"
	neighborNode_list = [7,8,11]
	neighborNode_port = {7:4,8:28,11:36}
	return signature,neighborNode_list,neighborNode_port,ip

def switch197_1():
	signature = 2
	ip = "192.168.123.197"
	neighborNode_list = [5,6,11]
	neighborNode_port = {5:132,6:156,11:164}
	return signature,neighborNode_list,neighborNode_port,ip

def switch197_2():
	signature = 4
	ip = "192.168.123.197"
	neighborNode_list = [7,8,11]
	neighborNode_port = {7:4,8:28,11:36}
	return signature,neighborNode_list,neighborNode_port,ip

def switch194_1():
	signature = 5
	ip = "192.168.123.194"
	# neighborNode_list = [1,9,12]
	# neighborNode_port = {1:140,9:132,12:164}
	neighborNode_list = [1,2,9,10,11]
	neighborNode_port = {1:140,2:148,9:132,10:156,11:164}
	# neighborNode_list = [1,7,12]
	# neighborNode_port = {1:140,7:172,12:164}
	return signature,neighborNode_list,neighborNode_port,ip


def switch194_2():
	signature = 7
	ip = "192.168.123.194"
	# neighborNode_list = [3,9,12]
	# neighborNode_port = {3:12,9:4,12:36}
	neighborNode_list = [3,4,9,10,11]
	neighborNode_port = {3:12,4:20,9:4,10:28,11:36}
	# neighborNode_list = [3,5,12]
	# neighborNode_port = {3:12,5:44,12:36}
	return signature,neighborNode_list,neighborNode_port,ip

def switch195_1():
	signature = 6
	ip = "192.168.123.195"
	neighborNode_list = [1,2,9,10,11]
	neighborNode_port = {1:140,2:148,9:132,10:156,11:164}
	return signature,neighborNode_list,neighborNode_port,ip

def switch195_2():
	signature = 8
	ip = "192.168.123.195"
	neighborNode_list = [3,4,9,10,11]
	neighborNode_port = {3:12,4:20,9:4,10:28,11:36}
	return signature,neighborNode_list,neighborNode_port,ip

def switch111_1():
	signature = 9
	ip = "192.168.123.111"
	neighborNode_list = [5,6,7,8,11]
	neighborNode_port = {5:132,6:140,7:148,8:156,11:164}
	return signature,neighborNode_list,neighborNode_port,ip

def switch111_2():
	signature = 10
	ip = "192.168.123.111"
	neighborNode_list = [5,6,7,8,11]
	neighborNode_port = {5:4,6:12,7:20,8:28,11:36}
	return signature,neighborNode_list,neighborNode_port,ip


          
def switch_address_recognition(ip,pipe):
	# print(ip)
	ip_last_three = '.'.join(ip.split('.')[3:])
	switch=ip_last_three+str(pipe)
	switcher = {
		1961:switch196_1,
		1960:switch196_2,
		1971:switch197_1,
		1970:switch197_2,
		1941:switch194_1,
		1940:switch194_2,
		1951:switch195_1,
		1950:switch195_2,
		1111:switch111_1,
		1110:switch111_2,
		# 1031:switch103_1,
		1030:switch103_2,
	}
	func = switcher.get(int(switch))
	return func()

def switch_id_recognition(signature):
	switcherID = {
		1: switch196_1,
		3: switch196_2,
		2: switch197_1,
		4: switch197_2,
		5: switch194_1,
		7: switch194_2,
		6: switch195_1,
		8: switch195_2,
		9: switch111_1,
		10:switch111_2,
		# 11:switch103_1,
		12:switch103_2
	}
	func = switcherID.get(int(signature))
	return func()

def clearTable(target,table):
		 table.entry_del(target)

def GetRegisterData(bfrt_info,target,register,register_idx):
		resp = register.entry_get(
			target,
			[register.make_key([gc.KeyTuple('$REGISTER_INDEX', register_idx)])])
		data, _ = next(resp)
		data_dict = data.to_dict()
		return data_dict

def AddRegisterData(bfrt_info,target,register,register_idx,register_val):
		register_val_name =register.info.name[5:]+".f1"
		resp = register.entry_mod(
			target,
			[register.make_key([gc.KeyTuple('$REGISTER_INDEX', register_idx)])],
			[register.make_data([
				gc.DataTuple(register_val_name, register_val)])])
def AddRegisterDataWithPipe(bfrt_info,target,register,register_idx,pipe,register_val):
		register_val_name =register.info.name[5:]+".f1"
		resp = register.entry_mod(
			target,
			[register.make_key([gc.KeyTuple('$REGISTER_INDEX', register_idx),gc.KeyTuple('$pipe', pipe)])],
			[register.make_data([
				gc.DataTuple(register_val_name, register_val)])])

def setMulticast(bfrt_info,target,mgid_table,node_table,brids,neighborNode_port_dict):
	###
    # multicast，todo:test and set the drop ddl
    # Dict to hold interface id for each port
    port_to_ifid = {}
    # Dict to hold multicast mgid for each bridge id
    brid_to_mgid = {}
    # Dict to hold multicast L1 id for each bridge id
    brid_to_l1 = {}
    

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
    num_pipes=2
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
    return brid_list	