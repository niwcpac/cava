#!/bin/bash 

#Helper script to copy relevant Ghidra settings out of the running virtual machine

if [ ! -d "/home/vagrant" ]; then
    echo "Script must be run within the cava-platform virtual machine. Exiting."
    exit
fi

CONFIG_DIR="/vagrant/bootstrap/ghidra/"
cd $CONFIG_DIR

# Archive existing settings if there are any
ARCHIVE="archive/"`date +"ghidra_settings-%Y-%m-%d--%H-%M-archived"`
if [ ! -f "$ARCHIVE" ]; then
    echo "Creating directory for archived settings: $ARCHIVE"
    mkdir $ARCHIVE
fi
if [ -f ghidra_settings.tgz ]; then
    mv ghidra_settings.tgz $ARCHIVE/
fi 
if [ -f ghidra_projects.tgz ]; then
    mv ghidra_projects.tgz $ARCHIVE/
fi
if [ -f ghidra_scripts.tgz ]; then
    mv ghidra_scripts.tgz $ARCHIVE/
fi


cd /home/vagrant
# Create tarballs of existing settings for later use
echo "Creating copy of settings directory: /home/vagrant/.ghidra"
tar -czf $CONFIG_DIR/ghidra_settings.tgz .ghidra

echo "Creating copy of Ghidra Project files *.rep and *.gpr under /home/vagrant/"
tar -czf $CONFIG_DIR/ghidra_projects.tgz *.rep *.gpr

echo "Creating copy of Ghidra Scripts: /home/vagrant/ghidra_scripts"
tar -czf $CONFIG_DIR/ghidra_scripts.tgz ghidra_scripts
