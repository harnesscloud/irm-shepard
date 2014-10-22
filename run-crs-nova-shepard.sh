#!/bin/bash
if [ ! $# -eq 2 ]; then
echo "$0 <crs-bin> <irm-nova>"
exit -1
fi

CRS_DIR=`dirname $1`
CRS=`basename $1`
NOVA_DIR=`dirname $2`
NOVA=`basename $2`
CURR_DIR=`pwd`

cd $CRS_DIR
./$CRS &
cd $CURR_DIR
cd $NOVA_DIR
./$NOVA -c nova-vagrant.cfg &> /dev/null &

cd $CURR_DIR
./irm-shepard.py &> /dev/null &

read
sleep 2

killall python









