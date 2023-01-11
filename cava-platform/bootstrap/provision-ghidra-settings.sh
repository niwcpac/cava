#!/bin/bash
source /tmp/provision-check.sh

# -----------------------------------------------------------------------
# Copy Ghidra Settings, Scripts, and Project Files to user home directory
#   Ghidra Scripts (~/ghidra_scripts) 
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Installing ghidra_scripts to: /home/vagrant/ghidra_scripts" | tee -a $PROVISION_LOG

cd /home/vagrant
tar -xzf $BOOTSTRAP/ghidra/ghidra_scripts.tgz >> $PROVISION_LOG
if [ ! -d /home/vagrant/ghidra_scripts ]; then
    mkdir /home/vagrant/ghidra_scripts
fi
chown -R vagrant:vagrant /home/vagrant/ghidra_scripts

# Ghidra settings (~/.ghidra)
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Installing ghidra_settings to: /home/vagrant/.ghidra" | tee -a $PROVISION_LOG

cd /home/vagrant
tar -xzf $BOOTSTRAP/ghidra/ghidra_settings.tgz >> $PROVISION_LOG
chown -R vagrant:vagrant /home/vagrant/.ghidra

# Ghidra Projects (~/*.rep, ~/*.gpr)
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Installing Ghidra project files (CavaTesting.rep, CavaTesting.gpr) to /home/vagrant/" | tee -a $PROVISION_LOG
cd /home/vagrant
tar -xzf $BOOTSTRAP/ghidra/ghidra_projects.tgz >> $PROVISION_LOG
chown vagrant:vagrant /home/vagrant/*.gpr
chown -R vagrant:vagrant /home/vagrant/*.rep

# Set up logging files for Ghidra Plugins
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Creating ghidra.log file at $LOG" | tee -a $PROVISION_LOG
touch $LOG/ghidra.log
chmod 666 $LOG/ghidra.log
