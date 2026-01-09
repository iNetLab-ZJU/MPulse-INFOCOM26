# grpc
---bf-sde-9.7.0/10.0---
<!-- need python-3.5.3 -->
sudo apt-get install python3-pip
pip3 install --upgrade pip
python3 -m pip install grpcio==1.17.0
python3 -m pip install grpcio-tools==1.17.0

#success!
python3 pktgen-grpc.py

if   
		ImportError: No module named 'scapy'

sudo pip install scapy
python3 -m pip install protobuf==3.6.1



# copy
'''

cat shortIp.txt | xargs -P0 -i -- sshpass -p onl -- scp -r ../pktgen root@192.168.123.{}:~/heart
scp r9@192.168.123.168:~/Documents/wd/pktgen-grpc.py wd/
scp r9@192.168.123.168:~/Documents/wd/pktgen.p4 wd/

'''
# scapy
sudo python3
class HeartBeat(Packet):
    name = "HeartBeat"
    fields_desc = [ BitField("heartbeat_type", 0, 1),
                    BitField("signature",0, 7),
                    BitField("Monitored_switch", 0, 7),
                    BitField("state", 0, 1),
                    BitField("protocol", 0x0800,16)]

bind_layers(Ether, HeartBeat, type=0x5520)


src_mac = "00:AA:BB:CC:DD:EE"
dst_mac = "00:EE:DD:CC:BB:AA"

p=Ether(src=src_mac, dst=dst_mac)/HeartBeat(Monitored_switch=0xB,signature=0xD,state=0,heartbeat_type=0)/IP(src="42.42.42.42" , dst="1.1.1.1")/TCP(dport=443, sport=0x1234)
sendp(p,iface='ens1f1',count=100)

# make
cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=pktgen -DP4_PATH=/root/heart/pktgen.p4
make justPort
make
make install


# faultDetection
#p4.Ingress.ipv4_host.add_with_send(
#    dst_addr=ip_address("192.168.1.1"), port=1)

#p4.Ingress.ipv4_lpm.add_with_send(
#   dst_addr=ip_address("192.168.1.0"), dst_addr_p_length=24,  port=64)
	
pipe.SwitchIngress.forward.add_with_l3_switch(ingress_port=68,port=140)

justPort.pipe.Ingress.forward.add_with_l3_switch(ingress_port=68,port=140)

justPort.pipe.Ingress.forward.add_with_l3_switch(
    ingress_port=156,port=140)


bfrt.complete_operations()

ucli 
pm
port-add -/- 100G RS
port-enb -/-

receive_heartbeat.entry_del(target,[receive_heartbeat.make_key([gc.KeyTuple('hdr.heartbeat.Monitored_switch', Monitored_switch),gc.KeyTuple('hdr.heartbeat.signature', signature)])])


# pktgen

tna_pktgen.pipe.SwitchIngress.t

p4.pipe.Ingress.forward.dump(table=True)


 for batch in range(4):
 	for pkt_num in range(20):
 		add_with_match(app_id=0,ingress_port=68,pipe_id=0,batch_id=batch,packet_id=pkt_num,port=140)

tf1.pktgen.port_cfg.entry(dev_port=68,pktgen_enable=True)

tf1.pktgen.app_cfg.add_with_trigger_timer_periodic(timer_nanosec=100,app_enable=False,pkt_len=100-6,pkt_buffer_offset=144,pipe_local_source_port=68,increment_source_port=False,batch_count_cfg=3,packets_per_batch_cfg=19,ibg=1,ibg_jitter=0,ipg=1000,ipg_jitter=500,batch_counter=0,pkt_counter=0,trigger_counter=0)


tf1.pktgen.pkt_buffer.add(pkt_buffer_offset=144,pkt_buffer_size=96,buffer='Ether / Dot1Q / IP / TCP 42.42.42.42:1234 > 1.1.1.1:https R')

# check ttl get
for pkt_num in range(p_count):
    resp = receive_heartbeat.entry_get(
        targetPipe,
        [receive_heartbeat.make_key([gc.KeyTuple('hdr.heartbeat.heatbeat_type',REPLY),gc.KeyTuple('hdr.heartbeat.Monitored_switch', neighborNode_list[pkt_num]),  
                              gc.KeyTuple('hdr.heartbeat.signature', signature)])],
        {"from_hw": True})
    data_dict = next(resp)[0].to_dict()
    print("###########one###########")
    print(data_dict)
    recv_ttl = data_dict["$ENTRY_TTL"]
    print(recv_ttl)


# snapshot
ucli
pipe_mgr
snap-create -d0 -p1 -i0 -s0 -e3
<!-- snap-trig-add -h 0x181 -n ig_intr_md_ingress_port -v 68 -m 0xffffffff -->
snap-trig-add -h 0x1181 -n hdr_heartbeat_heartbeat_type -v 180 -m 0xffffffff
snap-state-set -h 0x1181 -e 1
snap-state-get -h 0x1181   
snap-capture-get -h 0x1181


<!-- hdr_heartbeatheartbeat_type -->
src_mac = "00:AA:BB:CC:DD:EE"
dst_mac = "00:EE:DD:CC:BB:AA"
p=Ether(src=src_mac, dst=dst_mac)/IP(src="42.42.42.42" , dst="1.1.1.1")/TCP(dport=443, sport=1234)

# getip

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = socket.inet_ntoa(fcntl.ioctl(
    s.fileno(),
    0x8915, # SIOCGIFADDR
    struct.pack('256s', 'ma1'.encode('utf-8'))
)[20:24])



    # # Use the per-app counters to wait for all packets to be generated.
    # for _ in range(b_count * p_count):

    #   # verify pktgen related counters
    #   resp = pktgen_app.entry_get(
    #       targetPipe,
    #       [pktgen_app.make_key([gc.KeyTuple('app_id', 0)])],
    #       {"from_hw": True},
    #       pktgen_app.make_data([gc.DataTuple('batch_counter'),
    #                                       gc.DataTuple('pkt_counter'),
    #                                       gc.DataTuple('trigger_counter')],
    #                                        'trigger_timer_periodic', get=True)
    #   )
    #   data_dict = next(resp)[0].to_dict()
    #   tri_value = data_dict["trigger_counter"]
    #   if tri_value != 1:
    #       print("Triggered %d of 1 times"%(tri_value))
    #       # Wait for packets to be generated
    #       time.sleep(2)
    #       continue
    #   batch_value = data_dict["batch_counter"]
    #   if batch_value != b_count:
    #       print("Generated %d of %d batches"%(batch_value, b_count))
    #       # Wait for packets to be generated
    #       time.sleep(2)
    #       continue
    #   pkt_value = data_dict["pkt_counter"]
    #   if pkt_value != b_count * p_count:
    #       print("Generated %d of %d packets"%(pkt_value, b_count * p_count))
    #       # Wait for packets to be generated
    #       time.sleep(2)
    #       continue
    #   break


    # mode = bfruntime_pb2.Mode.SINGLE
<!-- # pktgen_self_timeFlow.attribute_entry_scope_set(target, predefined_pipe_scope=True,
#                                             predefined_pipe_scope_val=mode)
# pktgen_port.attribute_entry_scope_set(target, predefined_pipe_scope=True,
#                                             predefined_pipe_scope_val=mode)
# p_count_list = [0 for i in range(num_pipes)]  # packets per batch
# for i in range(num_pipes):
#     targetPipe = gc.Target(device_id=0, pipe_id=i)
#     signature,neighborNode_list,neighborNode_port = switch_address_recognition(ip,i)
#     p_count_list[i]=len(neighborNode_list)
#     print(p_count_list)
#     p_count_pre=0
#     if i!=0:
#         p_count_pre= sum(p_count_list[:i])
#     for batch in range(b_count):
#         for pkt_num in range(p_count_pre,p_count_pre+p_count_list[i]):
#           pktgen_self_timeFlow_key = pktgen_self_timeFlow.make_key([gc.KeyTuple('hdr.timer.app_id',0),gc.KeyTuple('ig_intr_md.ingress_port',pipe_local_port),gc.KeyTuple('hdr.timer.pipe_id',0),gc.KeyTuple('hdr.timer.batch_id',batch),gc.KeyTuple('hdr.timer.packet_id',pkt_num)])
#           pktgen_self_timeFlow_data = pktgen_self_timeFlow.make_data([gc.DataTuple('port',neighborNode_port.get(neighborNode_list[pkt_num-p_count_pre]))],'SwitchIngress.match')
#           pktgen_self_timeFlow.entry_add(targetPipe,[pktgen_self_timeFlow_key],[pktgen_self_timeFlow_data])
        
# p_count = sum(p_count_list)
## Configuring pktgen port -->