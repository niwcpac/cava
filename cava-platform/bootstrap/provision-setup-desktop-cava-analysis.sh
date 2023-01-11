#!/bin/bash
source /tmp/provision-check.sh

echo "------ Setting up Cava Analysis Desktop ------" | tee -a $PROVISION_LOG


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