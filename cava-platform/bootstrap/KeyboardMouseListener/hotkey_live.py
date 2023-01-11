import hotkey_library as HL
import json 


'''
This class can be given a file that loads hotkeys, the default file is for the default hotkeys 
in Ghidra. 

The object keyInterpreter is meant to be used in the following way. Using analyze_input, it takes a 
dictionary version of the json event that was created and it then returns all the possible hotkeys 
that the user possibly tried to use. 

@author Froylan Maldonado
'''


class keyInterpreter:

    # The object keeps track of the modifier keys that are pressed, and the previous event. 
    # The modifier keys are important in order to search of the possible hotkey.
    # prev_keyboardEvent is used for a heurestic.
    def __init__(self, hotkey_file="defaultKeyBindings"):

        self._hotkey_mappings = HL.load_hotkeys(hotkey_file)
        self._shift_pressed = False
        self._ctrl_pressed = False
        self._alt_pressed = False
        self._prev_keyboardEvent = None

    # This function takes a dictionary event, and does several checks to make sure it is a valid 
    # possible hotkey event
    def analyze_input(self, event):
        
        # Checks if event is a keyboard event
        keyboardEvent = event.get("KeyboardEvent")

        if keyboardEvent == None:
            return None, None

        # We need to check if the event is a modifier key. We keep track of the status of modifier keys.
        if HL.is_modifier(keyboardEvent):
            self._shift_pressed, self._ctrl_pressed, self._alt_pressed = HL.modifier_event(keyboardEvent, 
            self._shift_pressed, self._ctrl_pressed, self._alt_pressed)
            
            return None, None

        # If the even is not a modifier, and it is the release of the key, then we ignore it. 
        # We would be producing duplicate events for the same whole keystroke.
        if keyboardEvent.get("EventName") == "UP":
            return None, None

        # Makes sure the event passes heurestic 
        if  not live_heurestic(self._prev_keyboardEvent, keyboardEvent) :
            self._prev_keyboardEvent = keyboardEvent
            return None, None

        # Creates modifer string 
        mod_string = HL.create_mod_string(self._shift_pressed, self._ctrl_pressed, self._alt_pressed)

        # Receives possible hotkey and actions related to hotkey
        hotkey_string, actions = generate_actions(keyboardEvent, self._hotkey_mappings, mod_string)

        self._prev_keyboardEvent = keyboardEvent

        return hotkey_string, actions


# This is an arbritary heurestic that checks if the previous event and the 
# current event passed are temporally apart enough.
def live_heurestic(prev_keyboardEvent, keyboardEvent, threshold=.91):

    if prev_keyboardEvent == None:
        return True

    prev_timestamp = prev_keyboardEvent.get("Timestamp")
    curr_timestamp = keyboardEvent.get("Timestamp")

    diff = curr_timestamp - prev_timestamp

    # Previous testing has showed that .91 is a good heurestic.
    if diff > threshold:
        return True
    else: 
        return False

# Function gets the modifier string and creates the possible hotkey string made,
# it then gets all the possible actions associated with that hotkey.
def generate_actions(keyboardEvent, hotkey_mappings, mod_string):

    # ghidra_mapping is a dictionary defined in the Hotkey Library.
    # It essentially translates the SneakySnek mapping of a key to 
    # the ghidra version.
    key = HL.ghidra_mapping.get(keyboardEvent.get("Key"))

    if key == None:
        return None, None

    possible_hotkey = ""

    if mod_string == "":
        possible_hotkey = key
    else:
        possible_hotkey = mod_string +  "-" + key

    # hotkey_mappings is another translation dictionary we use to 
    # get the actions related to a specific hotkey.
    actions = hotkey_mappings.get(possible_hotkey)

    if actions == None:
        return None, None


    return possible_hotkey, actions