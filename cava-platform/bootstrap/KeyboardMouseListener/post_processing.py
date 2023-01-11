#! /usr/bin/env python3

import hotkey_library as HL
import json, argparse

'''
Post processing script that is meant to output possible hotkey uses in an lsl_data.json file.
This script requires a keybinding text file that has formatted keybindings. Refer to defaultKeyBindings
for format requirements. 

@author Froylan Maldonado
'''

'''
datafile = Type:list, list of json events that have the form of {"EventType" : Data } where Data is another json event

curr_index = Type:int, point in datafile the programmer wants to get events from

direction = Type:str, Which events does the programmer want to get, forward implies future events and backward is 
    previous events

EventType = Type:str, Event type to filter for. For list of types of events refer to cava-core documentation

numOfEvents = Type:int, Number of events to return

ignore_modifiers = Type:bool, if filtering for a KeyboardEvent, theres an additional option to ignore modifier keys.

requirements = Type:list, Additional requirements that an event must pass. This requires a special format like so,
                requirements = [ ["KEY","VAL"] , ["KEY2", "VAL2"] ]
                            #    requirementOne,  requirementTwo
'''
def get_events(datafile, curr_index, direction='forward', EventType='KeyboardEvent', numOfEvents=1,
ignore_modifiers=True, requirements=[]):

    if direction == 'forward':
        index_iter = iter(range(curr_index+1, len(datafile)))
    elif direction == 'backward':
        index_iter = iter(range(curr_index-1, -1, -1))
    else:
        print("ERROR: Unknown value for direction, ", direction)

    events_list = []
    count = 0

    for index in index_iter:
        # Note that curr_event is being assigned the Data field which should be another json object
        curr_event = datafile[index].get(EventType)

        # None if EventType doesn't have a value pair.
        if curr_event == None:
            continue
        else:
            if ignore_modifiers == True:
                if HL.is_modifier(curr_event):
                    continue
            #Checks additional requirements
            if HL.meets_requirements(curr_event, requirements) :
                events_list.append(curr_event)
                count += 1

        if count >= numOfEvents:
            return events_list

    return events_list

"""
This function is what determines if a specific event is a hotkeyevent.
The only hurestic right now is checking if the event is separated from other keyboardevents
by .9 secs (ignoring modifiers, and UP Events). This function may need additional tweaking later on.
"""
def is_hotkey_event(event, next_events, prev_events):

    if event.get("KeyboardEventType") == "UP":
        return False

    for ith_event in next_events:

        curr_timestamp = event.get("Timestamp")
        next_timestamp = ith_event.get("Timestamp")
        diff = next_timestamp - curr_timestamp

        if diff <= .9 :
            return False
    
    for ith_event in prev_events:

        curr_timestamp = event.get("Timestamp")
        prev_timestamp = ith_event.get("Timestamp")
        diff = curr_timestamp - prev_timestamp

        if diff <= .9 :
            return False

    return True
        

# checks if a given event has a mapped action.
# This also creates the HotKeyEvent if a list of actions exist.
def generate_possible_event(event, index, hotkey_mappings, datafile, mod_string):

    key = HL.ghidra_mapping.get(event.get("Key"))

    possible_hotkey = ""

    if mod_string == "":
        possible_hotkey = key
    else:
        possible_hotkey = mod_string +  "-" + key

    actions = hotkey_mappings.get(possible_hotkey)

    if actions == None:
        return index, datafile 

    timestamp = event.get("Timestamp")
    event_name = "GhidraHotKeyEvent"
    event_data = {"Timestamp" : timestamp, 
    "Hotkey": possible_hotkey,
    "Actions": actions}
    new_event = {event_name : event_data}
    next_index = index + 1

    datafile.insert(next_index, new_event)

    return next_index, datafile


# General logic for adding hotkey events t
def add_hotkey_events(datafile, hotkey_mappings):

    shift_pressed = False
    ctrl_pressed = False
    alt_pressed = False
    keyboardevents = 0
    index = 0

    while index < len(datafile):

        event = datafile[index].get("KeyboardEvent")
        
        if event == None : 
            index += 1
            continue

        if HL.is_modifier(event):
            shift_pressed, ctrl_pressed, alt_pressed = HL.modifier_event(event, 
            shift_pressed, ctrl_pressed, alt_pressed)
            index += 1
            continue
            
        next_events = get_events(datafile, index, direction="forward", numOfEvents=1, requirements=[["KeyboardEventType", "DOWN"]])
        prev_events = get_events(datafile, index, direction='backward', numOfEvents=1, requirements=[["KeyboardEventType", "DOWN"]])

        if is_hotkey_event(event, next_events, prev_events) :
            mod_string = HL.create_mod_string(shift_pressed, ctrl_pressed, alt_pressed)
            index, datafile = generate_possible_event(event, index, hotkey_mappings, datafile, mod_string)
            index += 1

        index += 1

    return datafile

def generate_output_file(datafile, outputfile):
    output = open(outputfile, "w")

    for event in datafile:
        output.write(json.dumps(event) + '\n')

    output.close()

def main():

    # This is command line argument parsing
    parser = argparse.ArgumentParser(description="Generate Hot Key detection events from lsl data file.")
    parser.add_argument("-i", "--inputfile", type=str, default='lsl_data.json', 
    help="path to file which needs hotkey events added (Default: lsl_data.json)")
    parser.add_argument("-o", "--outputfile", type=str, default='default.txt', 
    help="Output file name with added hotkey events (Default: default.txt)")
    parser.add_argument("-k", "--keybindings", type=str, default="defaultKeyBindings", 
    help="Keybinding file exported from experiment. (Default: defaultKeyBindings)")
    args = parser.parse_args()

    # Setting variables 
    inputfile = args.inputfile
    outputfile = args.outputfile
    keybindingfile = args.keybindings

    # Datafile is a list of json objects loaded from inputfile
    datafile = HL.load_json_file(inputfile)
    # Hotkey_mappings is a dictionary of hotkey bindings to a list of possible actions.
    # Note: keybindingfile is EXPECTED to be in a specific format. This file can be 
    # created by using CavaKeyBindingExporter. Found in cava-core in its own branch.  
    hotkey_mappings = HL.load_hotkeys(keybindingfile)

    mod_datafile = add_hotkey_events(datafile, hotkey_mappings)

    generate_output_file(mod_datafile, outputfile)

if __name__ == "__main__":
    main()