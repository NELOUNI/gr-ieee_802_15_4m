#!/bin/sh
cd /users/nae/gnuradio/src/gr-ieee_802_15_4m/examples/ 
source /users/nae/gnuradio/setup_env.sh
cp /home/nae/.gnuradio/config_p5.conf /home/nae/.gnuradio/config.config 
python tvClient.py -u \"addr=usrp12\" -f 626 -g 0 -v -p 9001 -W pwct1.ctl.nist.gov -s 6.25 -c /home/nae/TVWS/Demo/wusa_s6p25M_short_3 -d /users/nae/gnuradio/
