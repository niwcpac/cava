#!/bin/bash
source /tmp/provision-check.sh

# -----------------------------------------------------------------------
# Setup Keyboard and Mouse Instrumentation -- runs under python3
# Test with SneakySnek install with `python3 SneakySnekTest.py`
# Manually run with: `python3 KeyboardMouseListener.py`
# Run installed service with: `sudo systemctl start KeyboardMouseListener.service`
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Installing KeyboardMouseListener (sneakysnek)" | tee -a $PROVISION_LOG
echo ">>>>> 	and Lab Streaming Layer (LSL) pre-requisites" | tee -a $PROVISION_LOG
apt-get install -y python3-venv python3-pip python3-daemonize >> $PROVISION_LOG
pip3 install daemonize sneakysnek >> $PROVISION_LOG
#Install specific version of pylsl ... later versions do not include the library!! Grr.... 
pip3 install pylsl==1.14.0 >> $PROVISION_LOG

# Apply patch to sneakysnek to fix 'shift' key issue: https://github.com/SerpentAI/sneakysnek/issues/8
echo ">>>>> Applying patch to SneakySnek: https://github.com/SerpentAI/sneakysnek/issues/8" | tee -a $PROVISION_LOG
$BOOTSTRAP/apply-recorder-patch.sh $BOOTSTRAP


echo ">>>>> Installing GhidraImaging pre-requisites" | tee -a $PROVISION_LOG
    #Install Python3 required for image-based external instrumentation
    apt-get -y install python3-pip libjpeg-dev zlib1g-dev

    pip3 install --upgrade pip setuptools wheel

    #More packages for pytesseract-ocr libraries. This is image recognition.
    apt-get -y install tesseract-ocr libtesseract-dev libleptonica-dev pkg-config

    #Install pre-requisites for image-based external instrumentation
    pip3 install pillow pynput numpy opencv-python mss tesserocr pyautogui
    #Additional packages needed for pyautogui 
    apt-get install python3-tk python3-dev

echo ">>>>> Installing GhidraHotKey files for instrumentation" | tee -a $PROVISION_LOG

# ------------------------------------------------------------
# Install GhidraHotKey Instrumentation files
cd $BOOTSTRAP/KeyboardMouseListener/
chmod 755 hotkey_library.py hotkey_live.py defaultKeyBindings
cp hotkey_library.py $BIN
cp hotkey_live.py $BIN
cp defaultKeyBindings $BIN


echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Installing KeyboardMouseListener, LSL, and GhidraImaging service daemons to /opt/cava/" | tee -a $PROVISION_LOG
echo ">>>>>	Logs are captured under /opt/cava-log" | tee -a $PROVISION_LOG

# ------------------------------------------------------------
# Install the keyboard listener as a systemd daemon
cd $BOOTSTRAP/KeyboardMouseListener/
chmod 755 KeyboardMouseListener.py KeyboardMouseRunner
cp KeyboardMouseListener.py $BIN 
cp KeyboardMouseRunner $BIN
cp KeyboardMouseListener.service /etc/systemd/system/
systemctl enable KeyboardMouseListener.service


# ------------------------------------------------------------
# Install the LSL data forwarder as a systemd daemon
cd $BOOTSTRAP/KeyboardMouseListener/
chmod 755 LabStreamingLayer.py LabStreamingLayerRunner
cp LabStreamingLayer.py $BIN 
cp LabStreamingLayerRunner $BIN
cp LabStreamingLayer.service /etc/systemd/system/
systemctl enable LabStreamingLayer.service


# ------------------------------------------------------------
# Install the Ghidra image-based click logging systemd daemon
cd $BOOTSTRAP/ImageMonitoring/
#Change permissions, copy files to their respective directories, start the service.
chmod 755 ghidra_action_monitor.py ghidra_components.py ghidra_logger.py ghidra_runner ./images/*
cp ghidra_action_monitor.py $BIN
cp ghidra_components.py $BIN
cp ghidra_logger.py $BIN
cp ghidra_runner $BIN
if [ ! -d $BIN/images ]; then mkdir $BIN/images; fi
cp ./images/* $BIN/images/
cp ghidra_runner.service /etc/systemd/system/
systemctl enable ghidra_runner.service


# -----------------------------------------------------------------------
# Setting up monitoring daemons for Keyboard/Mouse and LSL logging
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Setting up helper scripts for starting and stopping monitoring daemons" | tee -a $PROVISION_LOG
cp $BOOTSTRAP/startCavaDaemons.sh /home/vagrant
cp $BOOTSTRAP/stopCavaDaemons.sh /home/vagrant
cp $BOOTSTRAP/viewCavaLogs.sh /home/vagrant
chmod 755 /home/vagrant/startCavaDaemons.sh
chmod 755 /home/vagrant/viewCavaLogs.sh
chmod 755 /home/vagrant/stopCavaDaemons.sh

echo 'export DISPLAY=":0.0"' >> /home/vagrant/.bashrc
echo 'export XAUTHORITY=/home/vagrant/.Xauthority' >> /home/vagrant/.bashrc
# Note: The service startup of the KeyboardMouseListener is 
#   dependent on X11 being already started. For whatever reason this is not working
#   on startup, probably due to not having the right WantedBy target for systemd
#   Also tried graphical.target rather than multi-user.target
#   Fix is the following: 
#       1. Enable easy manual lanching using a desktop toolbar shortcut (working)
#       2. Check and start process from within Ghidra CavaListener plugin (not yet completed)


echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Enable users to start/stop Monitoring services" | tee -a $PROVISION_LOG

echo "vagrant ALL= NOPASSWD: /bin/systemctl start KeyboardMouseListener.service" | (EDITOR="tee -a" visudo) >> $PROVISION_LOG
echo "vagrant ALL= NOPASSWD: /bin/systemctl stop KeyboardMouseListener.service" | (EDITOR="tee -a" visudo) >> $PROVISION_LOG
echo "vagrant ALL= NOPASSWD: /bin/systemctl start ghidra_runner.service" | (EDITOR="tee -a" visudo) >> $PROVISION_LOG
echo "vagrant ALL= NOPASSWD: /bin/systemctl stop ghidra_runner.service" | (EDITOR="tee -a" visudo) >> $PROVISION_LOG 
