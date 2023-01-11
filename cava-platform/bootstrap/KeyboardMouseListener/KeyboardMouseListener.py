#!/usr/bin/env python3

"""Monitors for Keyboard and Mouse interactions and forwards to a local UDP socket

@author Sunny Fugate
"""
import argparse
import json
import logging
import os
import signal
import socket
import sys
import time

import sneakysnek.keyboard_event
import sneakysnek.keyboard_keys
import sneakysnek.mouse_buttons
import sneakysnek.mouse_event
from daemonize import Daemonize
from sneakysnek.recorder import Recorder
import hotkey_live as hk

global process_logger
global data_logger
global recorder
global is_daemon
global hotkey_detector

UDP_IP = "127.0.0.1"
UDP_PORT = 1111
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
process_name = "KeyboardMouseListener"
log_path = "/opt/cava-log/"
default_data_log = "km_data.json"
keybindings_path = "/opt/cava/"


def setup_logger(name, log_file, log_level=logging.WARNING):
    logging.basicConfig(filename=log_file,
                        filemode='a',
                        level=log_level,
                        format='[%(levelname)s] (%(threadName)-10s) %(message)s')
    return logging.getLogger(name)


def event_handler(event):
    process_logger.debug("Handling event: " + str(event))
    event_dict = dict()
    
    if isinstance(event, sneakysnek.keyboard_event.KeyboardEvent):
        event_dict = {"KeyboardEvent":
                      {
                        "Timestamp": event.timestamp,
                        "InstrumentationType": "External",
                        "EventType": "KEYBOARD",
                        "EventName": event.event.name,
                        "EventSource": "KeyboardMouseListener",
                        "Key": event.keyboard_key.value
                     }}

    elif isinstance(event, sneakysnek.mouse_event.MouseEvent):
        event_dict = {"MouseEvent":
                      {
                        "Timestamp": event.timestamp,
                        "InstrumentationType": "External",
                        "EventType": "MOUSE",
                        "EventName": event.event.name,
                        "EventSource": "KeyboardMouseListener",
                        "X": event.x,
                        "Y": event.y,
                        "Button": None if event.button is None else event.button.value,
                        "Direction": event.direction,
                        "Velocity": event.velocity
                    }}

    else:
        process_logger.warning("Unhandled event")
        return

    # json_str = json.dumps(event_dict)+"\n"
    json_str = json.dumps(event_dict)
    hotkey_string, actions = hotkey_detector.analyze_input(event_dict)
    process_logger.debug("JSON:" + json_str)
    data_logger.info(json_str)
    sock.sendto(json_str.encode('utf-8'), (UDP_IP, UDP_PORT))

    if hotkey_string != None and actions != None:
        hotkey_dict = {"GhidraHotkeyEvent":
            {
                "Timestamp": event.timestamp,
                "InstrumentationType": "External",
                "EventType": "INFERRED_GHIDRA_HOTKEY",
                "EventName": "GhidraHotkey",
                "EventSource": "KeyboardMouseListener",
                "HotKey" : hotkey_string,
                "Actions" : actions
            }}

        json_hotkey = json.dumps(hotkey_dict)
        data_logger.info(json_hotkey)
        sock.sendto(json_hotkey.encode('utf-8'), (UDP_IP, UDP_PORT))


class ServiceExit(Exception):
    """ Simple exception for exiting threads """
    pass


def signal_handler(sig, frame):
    # def signal_handler(sig, frame):
    process_logger.info('Caught SIGINT / SIGTERM, flushing events, exiting')
    raise ServiceExit


def main():
    global sock
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    process_logger.info("Starting event capture")

    global recorder
    recorder = Recorder.record(event_handler)

    try: 
        while recorder.is_recording:
            # Busy wait to keep main thread alive
            time.sleep(1)
            pass

    except ServiceExit:
        # Stop event capture and wait for events to flush
        # recorder.stop() -- maybe not, causes exception in recorder class
        # time.sleep(1)

        # Close the socket
        # sock.close()

        # Exit the deamon
        # if is_daemon :
        #    daemon.exit()

        # Close logging file handlers
        # logging.shutdown()
        pass

    logging.info("Exiting program")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="Use verbose logging for process status", action="store_true")
    parser.add_argument("-s", "--stdout", help="Log event data to stdout", action="store_true")
    parser.add_argument("-f", "--file", help="Specify an additional file for logging data", type=str)
    parser.add_argument("-d", "--daemon", help="Run the listener as a demon", action="store_true")
    parser.add_argument("-l", "--log", help="Set the location for the process and data logs", type=str)

    args = parser.parse_args()

    # ---------- Setup logging directory if it doesn't exist
    if not os.path.isdir(log_path):
        os.mkdir(log_path)

    # ---------- Setup logging for the process 
    process_log_file = log_path + process_name + ".log"
    process_log_format = logging.Formatter('%(asctime)-15s %(message)s')
    process_log_handler = logging.FileHandler(process_log_file)
    process_log_handler.setFormatter(process_log_format)
    print("Setting up process log to "+process_log_file)
    process_logger = logging.getLogger(process_name+"-process")
    process_logger.addHandler(process_log_handler)

    # ---------- Setup hotkey instrumentation object
    hotkey_detector = hk.keyInterpreter(keybindings_path+"defaultKeyBindings")

    # processLogfile)

    if args.verbose:
        print("Verbose(DEBUG) logging enabled")
        process_logger.setLevel(logging.DEBUG)
    else:
        print("Non-verbose(WARN) logging enabled")
        process_logger.setLevel(logging.WARN)

    # Not sure what this setting does....
    # logger.propagate = False

    # ----------  Setup logging for the JSON event data 
    data_logger = logging.getLogger(process_name+"-data")
    data_logger.setLevel(logging.INFO)

    # Output to stdout if specified or if we are not using file output?
    if args.stdout:
        print("Logging to stdout")
        stdout_handler = logging.StreamHandler(sys.stdout)
        data_logger.addHandler(stdout_handler)
    if args.file:
        print("Logging to file: "+args.file)
        file_handler = logging.FileHandler(args.file)
        data_logger.addHandler(file_handler)
    else:
        data_file = log_path+default_data_log
        print("Logging to file: "+data_file)
        file_handler = logging.FileHandler(data_file)
        data_logger.addHandler(file_handler)

    # Add basics to run as a daemon - https://daemonize.readthedocs.io/en/latest/
    if args.daemon:
        print("Running as a daemon")
        is_daemon = True
        pid_file = "/var/run/" + process_name + ".pid"

        # Run the main program within a daemon context.  Do not close open file descriptors or we lose logging.
        daemon = Daemonize(app=process_name, pid=pid_file, action=main, auto_close_fds=False, logger=process_logger)
        daemon.start()
    else:
        main()
