# Keyboard and Mouse OS instrumentation

This folder contains all the files used for the OS instrumentation of the Mouse and Keyboard as well as Ghidra Hotkey detection scripts. It also contains the LsL python code for writing to the logs.

## Keyboard/Mouse Instrumentation

`KeyboardMouseListener.py` is the python script that initiates the system service for OS level instrumentation. We use the library [SneakySnek](https://github.com/SerpentAI/sneakysnek) with an added patch, `cava-platform/bootstrap/linux_recorder.patch`, that we developed. Refer to the respective scripts for additional information.

## Hotkey Instrumentation

`hotkey_library.py`: This is a python program that host helper functions for hotkey instrumentation.

`hotkey_live.py` : Python class that is meant to be called in `KeyboardMouseListener.py` for real-time hotkey instrumentation.

`post_processing.py` : Python program that can perform hotkey instrumentation post-experiment. 

`defaultKeyBindings` : Specially formatted text document that includes all default Ghidra KeyBindings. It's used by hotkey instrumentation to figure out what actions are mapped to what hotkeys. 

# Lab streaming layer 

The python program `LabStreamingLayer.py` listens in on a UDP port and then writes all the events that are pushed to that port to `/opt/cava-log/lsl_data.json` on the virtual machine.
