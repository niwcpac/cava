#!/bin/bash

source /tmp/provision-check.sh 
INSTALL_DIR="/home/vagrant/Desktop/CavaAnalysisTools"

echo "----- Installing Cava Analysis Tools ------" | tee -a $PROVISION_LOG

if [ -d "$INSTALL_DIR" ]; then mkdir $INSTALL_DIR; fi
cp -r /vagrant/cava-platform/cava-analysis $INSTALL_DIR
chown -R vagrant:vagrant $INSTALL_DIR

echo "-------- Finished installing Cava Analysis Tools -------" | tee -a $PROVISION_LOG