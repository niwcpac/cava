#!/bin/bash
source /tmp/provision-check.sh 

SCREEN_RESOLUTION="2560 1080 60"
DISPLAY_MODENAME="CavaPhase1_2560x1080_60hz"
VIRTUAL_DISPLAY="Virtual1"


echo "-----------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Updating the X11 Display Modes for Cava Experiment" | tee -a $PROVISION_LOG
echo ">>>>> Using resolution  [$SCREEN_RESOLUTION] with name [$DISPLAY_MODENAME] for display [$VIRTUAL_DISPLAY]" | tee -a $PROVISION_LOG


# Generate the modeline for our desired screen resolution and refresh rate
# gtf 2560 1080 60 
echo ">>>>> Generating the new modeline for our display" | tee -a $PROVISION_LOG
MODELINE=`gtf 2560 1080 60 | egrep "Modeline" | awk '{$1=$2=""; print $0}' | sed 's/^ *//'`


export DISPLAY=":0.0"
export XAUTHORITY=/home/vagrant/.Xauthority
#Wait until the display is ready
WAIT=1
while [ $WAIT ]; 
do
    xrandr | tee -a $PROVISION_LOG
    if [ $? -eq 0 ]; then break; fi
    echo ">>>>> Waiting for display to be ready for resolution changes" | tee -a $PROVISION_LOG
    sleep 1; 
done

# Create the new mode for use
echo ">>>>> Creating new display mode [$DISPLAY_MODENAME]" | tee -a $PROVISION_LOG
xrandr --newmode $DISPLAY_MODENAME $MODELINE

# Add the mode for the display
echo ">>>>> Adding the mode for the display [$VIRTUAL_DISPLAY]" | tee -a $PROVISION_LOG
xrandr --addmode $VIRTUAL_DISPLAY $DISPLAY_MODENAME 

# Change the output mode for the display
echo ">>>>> Updating the output mode, setting [$VIRTUAL_DISPLAY] to mode [$DISPLAY_MODENAME]" | tee -a $PROVISION_LOG
xrandr --output $VIRTUAL_DISPLAY --mode $DISPLAY_MODENAME

echo ">>>>> Verifying display mode " | tee -a $PROVISION_LOG
xrandr 
if xrandr | egrep "$DISPLAY_MODENAME" | egrep "\*"; then
    echo "-----------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
    echo ">>>>> Finished Display Configuration! " | tee -a $PROVISION_LOG
    echo ">>>>> Virtual machine should now be running at $SCREEN_RESOLUTION (x y freq)" | tee -a $PROVISION_LOG
    echo "-----------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
else
    echo "-----------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
    echo ">>>>> !! Display resolution updates failed !!" | tee -a $PROVISION_LOG
    echo ">>>>> !! The display could not be updated to the desired resolution ($SCREEN_RESOLUTION)" | tee -a $PROVISION_LOG
    echo ">>>>> !! If the mode is available, you may try to set the display manually using xrandr as follows:" | tee -a $PROVISION_LOG
    echo ">>>>>      xrandr --output $VIRTUAL_DISPLAY --mode $DISPLAY_MODENAME" | tee -a $PROVISION_LOG
    echo "-----------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
fi
