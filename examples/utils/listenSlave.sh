#!/bin/bash     
xterm -hold -e "ncat -u -l -p 3333 | tee listenSlave"
