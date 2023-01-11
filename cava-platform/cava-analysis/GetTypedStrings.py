"""
@author Froylan Maldonddo

This script takes a Keyboard log file and outputs json events with strings that a subject possibly typed.

"""

import json
import argparse


def create_typing_string(typed) -> str:
    """
    Returns string of keys that were typed given a list of keyboard events

    Args:
         @param typed: List of keyboard json events
    """

    typed_string = ""

    # This section tries to replicate the string that would've appeared on-screen while
    # typing
    for event in typed:
        key = event.get("KeyboardEvent").get("Key")

        if key == "KEY_BACKSPACE" or key == "KEY_DELETE":
            typed_string = typed_string[:-1]
            continue

        transformed = charMapping.get(key)

        if transformed is None:
            continue

        typed_string += transformed

    return typed_string


def main():
    parser = argparse.ArgumentParser(description="Generate typed events based on given km_data.json file.")
    parser.add_argument("-i", "--inputfile", type=str, default='km_data.json',
                        help="path to event data (Default: km_data.json)")
    parser.add_argument("-o", "--outputfile", type=str, default='default.txt',
                        help="Output file name for typed events (Default: default.txt)")
    args = parser.parse_args()

    # Setting variables
    inputfile = args.inputfile
    outputfile = args.outputfile

    # Datafile is a list of json objects loaded from inputfile
    typed_events = []
    current_string = []
    keyboard_file = open(inputfile, 'r')

    while True:

        line = keyboard_file.readline()

        # We need to consider that the last keystroke was part of a typed string
        if line is None or line is "":
            if len(current_string) > 1:
                typed = create_typing_string(current_string)
                typing_event = {
                    "TypingEvent":
                        {
                            "String": typed,
                            "InitialTimestamp": current_string[0].get("KeyboardEvent").get("Timestamp"),
                            "EndingTimestamp": current_string[-1].get("KeyboardEvent").get("Timestamp")
                        }
                }
                typed_events.append(typing_event)
            break

        keyboard_event = json.loads(line)

        data = keyboard_event.get("KeyboardEvent")

        # Checking if the loaded json object is a KeyboardEvent
        if data is None:
            continue

        # Since there's an up and down stroke for every keystroke, we arbitrarily decided to ignore up strokes.
        if data.get("EventName") == "UP":
            continue

        # Checks if the current_string is empty, if it is then the current keystroke is a singleton, go to the
        # next event and get more events.
        if not current_string:
            current_string.append(keyboard_event)
            continue

        curr_event_timestamp = data.get("Timestamp")
        last_event_timestamp = current_string[-1].get("KeyboardEvent").get("Timestamp")
        diff = curr_event_timestamp - last_event_timestamp

        # If the difference between the last keystroke and the current one is more than .91 seconds, then
        # they belong to two different typed strings. We then construct the typed string, and reset current_string.
        if diff > .91:
            if len(current_string) > 1:
                typed = create_typing_string(current_string)
                typing_event = {
                    "TypingEvent":
                        {
                            "String": typed,
                            "InitialTimestamp": current_string[0].get("KeyboardEvent").get("Timestamp"),
                            "EndingTimestamp": current_string[-1].get("KeyboardEvent").get("Timestamp")
                        }
                }
                typed_events.append(typing_event)

            current_string = [keyboard_event]
            continue

        current_string.append(keyboard_event)

    keyboard_file.close()
    typing_event_file = open(outputfile, 'w')

    for event in typed_events:
        typing_event_file.write(json.dumps(event) + '\n')

    typing_event_file.close()


modifiers = ['KEY_LEFT_CTRL',
             'KEY_RIGHT_CTRL',
             'KEY_LEFT_ALT',
             'KEY_RIGHT_ALT'
             ]

charMapping = {
    'KEY_SPACE': ' ',
    'KEY_APOSTROPHE': "'",
    'KEY_EQUALS': '=',
    'KEY_COMMA': ',',
    'KEY_MINUS': '-',
    'KEY_PERIOD': '.',
    'KEY_SLASH': '/',
    'KEY_SEMICOLON': ';',
    'KEY_LEFT_BRACKET': '[',
    'KEY_RIGHT_BRACKET': ']',
    'KEY_BACKSLASH': '\\',
    'KEY_GRAVE': '`',
    'KEY_0': '0',
    'KEY_1': '1',
    'KEY_2': '2',
    'KEY_3': '3',
    'KEY_4': '4',
    'KEY_5': '5',
    'KEY_6': '6',
    'KEY_7': '7',
    'KEY_8': '8',
    'KEY_9': '9',
    'KEY_NUMPAD_0': '0',
    'KEY_NUMPAD_1': '1',
    'KEY_NUMPAD_2': '2',
    'KEY_NUMPAD_3': '3',
    'KEY_NUMPAD_4': '4',
    'KEY_NUMPAD_5': '0',
    'KEY_NUMPAD_6': '6',
    'KEY_NUMPAD_7': '7',
    'KEY_NUMPAD_8': '8',
    'KEY_NUMPAD_9': '9',
    'KEY_A': 'a',
    'KEY_B': 'b',
    'KEY_C': 'c',
    'KEY_D': 'd',
    'KEY_E': 'e',
    'KEY_F': 'f',
    'KEY_G': 'g',
    'KEY_H': 'h',
    'KEY_I': 'i',
    'KEY_J': 'j',
    'KEY_K': 'k',
    'KEY_L': 'l',
    'KEY_M': 'm',
    'KEY_N': 'n',
    'KEY_O': 'o',
    'KEY_P': 'p',
    'KEY_Q': 'q',
    'KEY_R': 'r',
    'KEY_S': 's',
    'KEY_T': 't',
    'KEY_U': 'u',
    'KEY_V': 'v',
    'KEY_W': 'w',
    'KEY_X': 'x',
    'KEY_Y': 'y',
    'KEY_Z': 'z'
}

main()
