#!/bin/bash


#---------- Boilerplate helpers for use if script is run standalone ----------------
if [ `whoami` != root ]; then echo "Please run this script as root or using sudo"; exit; fi

if [ -z "$BIN" ]; then BIN="/opt/cava/"; fi
if [ ! -d "$BIN" ]; then mkdir $BIN; fi

if [ -z "$LOG" ]; then LOG="/opt/cava-log/"; fi
if [ ! -d "$LOG" ]; then mkdir $LOG; fi

if [ -z "$PROVISION_LOG" ]; then PROVISION_LOG="/dev/null"; fi
touch $PROVISION_LOG

if [ -z "$BOOTSTRAP" ]; then BOOTSTRAP="/vagrant/bootstrap"; fi
if [ ! -d "$BOOTSTRAP" ]; then 
    echo "Bootstrap directory $BOOTSTRAP wasn't found, assuming development environment"
    BOOTSTRAP="/vagrant/cava-platform/bootstrap" 
    echo "Using bootstrap directory $BOOTSTRAP"
fi

if [ ! -d "$BOOTSTRAP" ]; then
    echo "!!!! Vagrant bootstrap folder not found at /vagrant/bootstrap.  "
    echo "  This is usuallly either a guest additions issue or VPN issue."
    echo "  Please check the base box to ensure guest additions are up to date."
    echo "  If you are on VPN, please disconnect before starting the virtual machine."
    echo "\n\n!!!! VM not provisioned. Exiting"
    exit 2
fi

# Make apt-get work in noninteractive mode
export DEBIAN_FRONTEND=noninteractive


