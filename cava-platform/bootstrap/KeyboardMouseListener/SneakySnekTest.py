#!/usr/bin/python

from sneakysnek.recorder import Recorder
import sneakysnek.keyboard_event
import sneakysnek.keyboard_keys

import time


def eventHandler(event):
    print(event)

    if isinstance(event, sneakysnek.keyboard_event.KeyboardEvent):
        if event.keyboard_key == sneakysnek.keyboard_keys.KeyboardKey.KEY_ESCAPE:
            global recorder
            recorder.stop()



def main():
    print("Starting keyboard and mouse event capture")
    global recorder
    recorder = Recorder.record(eventHandler)

    while(recorder.is_recording):
        #Busy wait to keep main thread alive
        time.sleep(1)
        pass



if __name__ == "__main__":
    main()

