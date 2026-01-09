# for the zuhe folder
cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=codepipe -DP4_PATH=/root/pktgen/zuhe/twopipe.p4

./run_switchd.sh -p codepipe -c twopipe_bfrt.conf


cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=codepipe -DP4_PATH=/root/heart/pktgen-controlBigTopoActionProfile.p4

cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DTOFINO=OFF -DTOFINO2=ON -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=code -DP4_PATH=/root/heart/multi/BigTopo/TryMatch/pktgen-controlBigTopoActionProfile.p4
~/bf-sde-9.10.0/run_switchd.sh -p code --arch tf2


cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DTOFINO=ON -DTOFINO2=OFF -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=code -DP4_PATH=/root/heart/TryMatch/pktgen-other194.p4

./run_switchd.sh -p code -c twopipe_bfrt.conf


cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL -DTOFINO=ON -DTOFINO2=OFF -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=code -DP4_PATH=/root/heart/multi/BigTopo/TryMatch/pktgen-other103.p4

./run_iterm_commands.sh