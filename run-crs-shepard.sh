#!/bin/bash
if [ ! $# -eq 1 ]; then
echo "$0 <crs-bin>"
exit -1
fi

CRS_DIR=`dirname $1`
CRS=`basename $1`
CURR_DIR=`pwd`
echo $CRS_DIR
echo $CURR_DIR

cd $CRS_DIR
./$CRS &
CRS_PID=$!
cd $CURR_DIR
./irm-shepard.py &> /dev/null &
SHEPARD_PID=$!
read
sleep 1

killall python









