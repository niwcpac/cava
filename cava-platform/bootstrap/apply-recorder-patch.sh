#!/bin/bash
<<COMMENT

We are using the public library SneakySnek to instrument the Mouse and Keyboard
at the OS level. The version of linux that we are using has compatibility issues 
with SneakySnek that causes some bugs. This patch file modifies the keycode mappings
for our linux distribution in SneakySnek.

@author Froylan Maldonado
COMMENT

SNEAKYSNEK_PATH=$(pip3 show sneakysnek | grep Location | sed 's/Location://')
PATCH_FILE_LOC=$1
VERSION=$(pip3 show sneakysnek | grep Version | sed 's/Version: //')

if [ "$VERSION" != "0.1.1" ]; then
    echo "Sneakysnek version: $(VERSION). Not applying patch."
    exit 0
else
    echo "Applying sneakysnek patch..."
fi

cd $SNEAKYSNEK_PATH/sneakysnek/recorders

sudo patch < $PATCH_FILE_LOC/linux_recorder.patch
