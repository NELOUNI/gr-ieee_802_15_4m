#!/bin/sh
sudo rm .master.pid
#python master_transceiver_OQPSK.py --source socket -G remote -a pwct1.ctl.nist.gov -u "addr=usrp4" -f 626 & echo $! > .master.pid
#sudo -H LD_LIBRARY_PATH=$LD_LIBRARY_PATH PYTHONPATH=$PYTHONPATH python master_transceiver_OQPSK.py --source tuntap -G remote -a pwct1.ctl.nist.gov -u "addr=usrp4" -f 626 & echo $! > .master.pid
#export DISPLAY=:0
#sudo xauth add $(xauth -f ~/.Xauthority list|tail -1)
#sudo -H LD_LIBRARY_PATH=$LD_LIBRARY_PATH PYTHONPATH=$PYTHONPATH python master_transceiver_OQPSK.py --source tuntap -G remote -a pwct1.ctl.nist.gov -u "addr=usrp4" -f 626 & echo $! > .master.pid
python master_transceiver_OQPSK.py --source socket -G remote -a pwct1.ctl.nist.gov -u "addr=usrp4" -f 626 & echo $! > .master.pid
