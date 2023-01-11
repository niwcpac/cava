#Steps for manually copying system and desktop environment settings

1. Configuration for XFCE Session to disable screensaver and power management
`cp /home/vagrant/.config/xfce4/xinitrc /vagrant/bootstrap/xinitrc`

2. Configuration for the desktop environment
`cp /usr/share/lightdm/lightdm.conf.d/01_debian.conf /vagrant/bootstrap/lightdm-01_debian.conf`

3. XFCE Panel Launchers
`cp /home/vagrant/.config/xfce4/panel/launcher-16/CavaStartup.desktop /vagrant/boostrap/CavaStartup.desktop`
`cp /home/vagrant/.config/xfce4/panel/launcher-16/CavaVerify.desktop /vagrant/boostrap/CavaVerify.desktop`
`cp /home/vagrant/.config/xfce4/panel/launcher-16/CavaShutdown.desktop /vagrant/boostrap/CavaShutdown.desktop`

4. XFCE Dock/Panels
`cd /home/vagrant/.config/xfce4/xfconf/`
`tar -czvf /vagrant/bootstrap/xfce-perchannel-xml.tgz xfce-perchannel-xml`
