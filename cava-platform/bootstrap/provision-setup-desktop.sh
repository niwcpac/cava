#!/bin/bash 
source /tmp/provision-check.sh

# Port all xfce4 settings folder to cava-platform
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Porting all XFCE settings" | tee -a $PROVISION_LOG
cd /home/vagrant/.config/
tar -xzvf $BOOTSTRAP/xfce4.tgz 

# -----------------------------------------------------------------------
# Disable Screen Lock, Screen saver, and Power management display management
# Handled in xinitrc
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Setting up XFCE Session to Disable Screensaver and Power Management" | tee -a $PROVISION_LOG
cp $BOOTSTRAP/xinitrc /home/vagrant/.config/xfce4/xinitrc
chown vagrant:vagrant /home/vagrant/.config/xfce4/xinitrc
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Setting up LightDM to auto-login as the vagrant user" | tee -a $PROVISION_LOG
cp $BOOTSTRAP/lightdm-01_debian.conf /usr/share/lightdm/lightdm.conf.d/01_debian.conf


echo "-----------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Setting up desktop panel launcher for XFCE" | tee -a $PROVISION_LOG

cp $BOOTSTRAP/CavaStartup.desktop /home/vagrant/.config/xfce4/panel/launcher-16
cp $BOOTSTRAP/CavaVerify.desktop /home/vagrant/.config/xfce4/panel/launcher-16
cp $BOOTSTRAP/CavaShutdown.desktop /home/vagrant/.config/xfce4/panel/launcher-16

cp $BOOTSTRAP/Terminal.desktop /home/vagrant/.config/xfce4/panel/launcher-4

# Fix up permissions
chown -R vagrant:vagrant /home/vagrant/.config/xfce4/


