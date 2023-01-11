#!/bin/bash
source /tmp/provision-check.sh

# Fix obnoxious dpkg errors
export DEBIAN_FRONTEND=noninteractive

# Update package database
echo ">>>>> Updating package database" | tee -a $PROVISION_LOG

apt-get update >> $PROVISION_LOG
apt-get install -y python-pip >> $PROVISION_LOG

