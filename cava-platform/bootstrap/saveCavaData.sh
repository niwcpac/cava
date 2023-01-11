#!/bin/bash

LOG_DIR="/opt/cava-log"
DATE=$(date +"%d-%m-%Y-%H%M%S")
DATA_DIR="/vagrant/cava-data/cava-run-$DATE"
CAVA_DATA_DIR="/vagrant/cava-data"
TOOL_DIR="/vagrant/bootstrap"
PROJECT_DIR="/home/vagrant"

echo "----- Saving all cava subject data -----"

#This should never happen unless the script is called successively very quickly
if [ -d "$DATA_DIR" ]; then
    sleep 1
    DATE=$(date +"%d-%m-%Y-%H%M%S")
    DATA_DIR="/vagrant/cava-data/cava-run-$DATE"
fi

sudo mkdir $DATA_DIR

sudo cp -R $LOG_DIR/* $DATA_DIR/

cd $PROJECT_DIR
sudo tar -czf $DATA_DIR/"ghidra_project_files_$DATE.tgz" *.gpr *.rep
