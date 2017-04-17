#python slave_transceiver_OQPSK.py -u "addr=usrp3" --source socket -f 626 & echo $! > .slave.pid
#export DISPLAY=:0
sudo xauth add $(xauth -f ~/.Xauthority list|tail -1)
sudo -H LD_LIBRARY_PATH=$LD_LIBRARY_PATH PYTHONPATH=$PYTHONPATH python slave_transceiver_OQPSK.py -u "addr=usrp3" --source tuntap -f 626 & echo $! > .slave.pid
