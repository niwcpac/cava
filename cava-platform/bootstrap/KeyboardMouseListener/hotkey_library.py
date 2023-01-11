import json
import argparse

'''
Python library meant to contain helper functions and dictionaries for hotkey detection

@author Froylan Maldonado
'''


# Maps sneakysnek keyboard mappings style to Ghidra's hotkey mappings style
ghidra_mapping = {
    "KEY_ESCAPE" : "ESCAPE",
    "KEY_F1" : "F1",
    "KEY_F2" : "F2",
    "KEY_F3" : "F3",
    "KEY_F4" : "F4",
    "KEY_F5" : "F5",
    "KEY_F6" : "F6",
    "KEY_F7" : "F7",
    "KEY_F8" : "F8",
    "KEY_F9" : "F9",
    "KEY_F10" : "F10",
    "KEY_F11" : "F11",
    "KEY_F12" : "F12",
    "KEY_GRAVE" : "BACK_QUOTE",
    "KEY_1" : "1",
    "KEY_2" : "2",
    "KEY_3" : "3",
    "KEY_4" : "4",
    "KEY_5" : "5",
    "KEY_6" : "6",
    "KEY_7" : "7",
    "KEY_8" : "8",
    "KEY_9" : "9",
    "KEY_0" : "0",
    "KEY_MINUS" : "MINUS",
    "KEY_EQUALS" : "EQUALS",
    "KEY_BACKSPACE" : "BACKSPACE",
    "KEY_INSERT" : "INSERT",
    "KEY_HOME" : "HOME",
    "KEY_PAGE_UP" : "PAGE_UP",
    "KEY_TAB" : "TAB",
    "KEY_Q" : "Q",
    "KEY_W" : "W",
    "KEY_E" : "E",
    "KEY_R" : "R",
    "KEY_T" : "T",
    "KEY_Y" : "Y",
    "KEY_U" : "U",
    "KEY_I" : "I",
    "KEY_O" : "O",
    "KEY_P" : "P",
    "KEY_LEFT_BRACKET" : "OPEN_BRACKET",
    "KEY_RIGHT_BRACKET" : "CLOSE_BRACKET",
    "KEY_BACKSLASH" : "BACK_SLASH",
    "KEY_DELETE" : "DELETE",
    "KEY_END" : "END",
    "KEY_PAGE_DOWN" : "PAGE_DOWN",
    "KEY_A" : "A",
    "KEY_S" : "S",
    "KEY_D" : "D",
    "KEY_F" : "F",
    "KEY_G" : "G",
    "KEY_H" : "H",
    "KEY_J" : "J",
    "KEY_K" : "K",
    "KEY_L" : "L",
    "KEY_SEMICOLON" : "SEMICOLON",
    "KEY_APOSTROPHE" : "QUOTE",
    "KEY_LEFT_SHIFT" : "SHIFT",
    "KEY_Z" : "Z",
    "KEY_X" : "X",
    "KEY_C" : "C",
    "KEY_V" : "V",
    "KEY_B" : "B",
    "KEY_N" : "N",
    "KEY_M" : "M",
    "KEY_COMMA" : "COMMA",
    "KEY_PERIOD" : "PERIOD",
    "KEY_SLASH" : "SLASH", 
    "KEY_RIGHT_SHIFT" : "SHIFT",
    "KEY_UP" : "UP",
    "KEY_LEFT_CTRL" : "CTRL",
    "KEY_LEFT_ALT" : "ALT",
    "KEY_SPACE" : "SPACE", 
    "KEY_RIGHT_ALT" : "ALT",
    "KEY_RIGHT_CTRL" : "CTRL",
    "KEY_LEFT" : "LEFT",
    "KEY_DOWN" : "DOWN",
    "KEY_RIGHT" : "RIGHT"
}

# Loads the json object file and loads it on a list where each index is a json object of the form
# {"EventType": Data } where Data is a nested json object
def load_json_file(inputfile):
    data = []

    with open(inputfile) as f:
        for line in f:
            temp = json.loads(line)
            data.append(temp)

    return data

# Loads the hotkeys from a given Keybindingfile. Note that this keybinding file has a specific format 
# that can be created using the KeyBindingExporterPlugin from KeyBindingExporter Branch on cava-core
def load_hotkeys(keybindingfile):
    hotkeys = {}

    with open(keybindingfile) as file:
        for line in file:
            action = " ".join(line.split()).split("|")
        
            if action[1] == '':
                continue
        
            entry = hotkeys.get(action[1].upper().strip())
        
            if entry == None:
                hotkeys[action[1].upper().strip()] = [action[0].upper()]
            else:
                action_description = hotkeys.get(action[1].upper().strip())
                action_description.append(action[0].upper())

    return hotkeys

# Simply checks if the given keyboardEvent is a modifier
def is_modifier(keyboardEvent):

    key = ghidra_mapping.get(keyboardEvent.get("Key"))
    modifiers = ["SHIFT", "CTRL", "ALT"]

    if key in modifiers:
        return True
    else:
        return False

# This functions sets bools set to True is a modifier is currently being presed 
# and false for the opposite
def modifier_event(keyboardEvent, shift_pressed, ctrl_pressed, alt_pressed):

    key = ghidra_mapping.get(keyboardEvent["Key"])

    if keyboardEvent["EventName"] == "DOWN":
        
        if key == "SHIFT":
            shift_pressed = True
        if key == "CTRL":
            ctrl_pressed = True
        if key == "ALT":
            alt_pressed = True
    
    else:
        
        if key == "SHIFT":
            shift_pressed = False
        if key == "CTRL":
            ctrl_pressed = False
        if key == "ALT":
            alt_pressed = False

    return shift_pressed, ctrl_pressed, alt_pressed

# This checks if the event meets additional requirements that the programmer has set for a specific 
# event
def meets_requirements(event, list_requirements):

    for req in list_requirements:
        if  req[1] != event.get(req[0]) :
            return False

    return True

def is_modifier(keyboardEvent):

    key = ghidra_mapping.get(keyboardEvent.get("Key"))
    modifiers = ["SHIFT", "CTRL", "ALT"]

    if key in modifiers:
        return True
    else:
        return False

# Creates suffix of a possible hotkey if modifiers were pressed 
def create_mod_string(shift_pressed, ctrl_pressed, alt_pressed):

    mod_string = ""

    if ctrl_pressed:
        mod_string += "CTRL"
    if alt_pressed:
        if mod_string == "":
            mod_string += "ALT"
        else:
            mod_string +="-ALT"
    if shift_pressed:
        if mod_string == "":
            mod_string +="SHIFT"
        else:
            mod_string += "-SHIFT"

    return mod_string