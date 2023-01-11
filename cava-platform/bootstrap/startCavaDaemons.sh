#!/bin/bash

LOGDIR="/opt/cava-log"
km_log=$LOGDIR/KeyboardMouseListener.log
lsl_log=$LOGDIR/LabStreamingLayer.log
gc_log=$LOGDIR/GhidraClickLogs.log

echo ">>>> Starting the LabStreamingLayer forwarding service" | sudo tee -a $lsl_log
echo "sudo systemctl start LabStreamingLayer" | sudo tee -a $lsl_log
sudo systemctl start LabStreamingLayer > /dev/null
sudo systemctl status LabStreamingLayer | sudo tee -a $lsl_log > /dev/null

lsl_active=`sudo service LabStreamingLayer status | egrep "Active: active"`
if [ -n "$lsl_active" ]; then
	echo ">>>> LabStreamingLayer service is running." | sudo tee -a $lsl_log
else
	echo "!!!! Failure: LabStreamingLayer service could not be started" | sudo tee -a $lsl_log
	echo "	View service status under $lsl_log"
fi

echo "------------------------------------------------"

echo ">>>> Starting the KeyboardMouseListener service" | sudo tee -a $km_log
echo "sudo systemctl start KeyboardMouseListener" | sudo tee  -a $km_log
sudo systemctl start KeyboardMouseListener > /dev/null
sudo systemctl status KeyboardMouseListener | sudo tee -a $km_log > /dev/null

km_active=`sudo service KeyboardMouseListener status | egrep "Active: active"`
if [ -n "$km_active" ]; then
	echo ">>>> KeyboardMouseListener service is running." | sudo tee -a $km_log
else
	echo "!!!! Failure: KeyboardMouseListener service could not be started" | sudo tee  -a $km_log
	echo "	View service status under $km_log"
fi

echo "------------------------------------------------"

echo ">>>> Starting the ghidra_runner service" | sudo tee -a $gc_log
echo "sudo systemctl start ghidra_runner" | sudo tee  -a $gc_log
sudo systemctl start ghidra_runner > /dev/null
sudo systemctl status ghidra_runner | sudo tee -a $gc_log > /dev/null

gc_active=`sudo service ghidra_runner status | egrep "Active: active"`
if [ -n "$gc_active" ]; then
	echo ">>>> ghidra_runner service is running." | sudo tee -a $gc_log
else
	echo "!!!! Failure: ghidra_runner service could not be started" | sudo tee  -a $gc_log
	echo "	View service status under $gc_log"
fi

echo "Finished"
sleep 5
