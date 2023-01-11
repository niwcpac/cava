#!/bin/bash

LOGDIR="/opt/cava-log"
km_log=$LOGDIR/KeyboardMouseListener.log
lsl_log=$LOGDIR/LabStreamingLayer.log
gc_log=$LOGDIR/GhidraClickLogs.log

echo ">>>> Stopping the LabStreamingLayer" | sudo tee -a $lsl_log
echo "> sudo systemctl stop LabStreamingLayer" | sudo tee -a $lsl_log
sudo systemctl stop LabStreamingLayer > /dev/null
sudo systemctl status LabStreamingLayer | sudo tee -a $lsl_log > /dev/null

lsl_active=`sudo service LabStreamingLayer status | egrep "Active: inactive"`
if [ -n "$lsl_active" ]; then
	echo ">>>> LabStreamingLayer service is inactive." | sudo tee -a $lsl_log
else
	echo "!!!! Failure: LabStreamingLayer service could not be shutdown" | sudo tee -a $lsl_log
	echo "	View service status under $lsl_log"
fi

echo "------------------------------------------------"


echo ">>>> Stopping the KeyboardMouseListener" | sudo tee -a $km_log
echo "> sudo systemctl stop KeyboardMouseListener" | sudo tee -a $km_log
sudo systemctl stop KeyboardMouseListener > /dev/null
sudo systemctl status KeyboardMouseListener | sudo tee -a $km_log > /dev/null

km_active=`sudo service KeyboardMouseListener status | egrep "Active: inactive"`
if [ -n "$km_active" ]; then
	echo ">>>> KeyboardMouseListener service is inactive." | sudo tee -a $km_log
else
	echo "!!!! Failure: KeyboardMouseListener service could not be shutdown" | sudo tee -a $km_log
	echo "	View service status under $km_log"
fi

echo "------------------------------------------------"

echo ">>>> Stopping the ghidra_runner" | sudo tee -a $km_log
echo "> sudo systemctl stop ghidra_runner" | sudo tee -a $km_log
sudo systemctl stop ghidra_runner > /dev/null
sudo systemctl status ghidra_runner | sudo tee -a $km_log > /dev/null

gc_active=`sudo service ghidra_runner status | egrep "Active: inactive"`
if [ -n "$gc_active" ]; then
	echo ">>>> ghidra_runner service is inactive." | sudo tee -a $km_log
else
	echo "!!!! Failure: ghidra_runner service could not be shutdown" | sudo tee -a $km_log
	echo "	View service status under $km_log"
fi

echo "Finished"
sleep 5
