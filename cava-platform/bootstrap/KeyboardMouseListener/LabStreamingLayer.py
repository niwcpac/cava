#!/usr/bin/env python

"""Receives UDP packets and forwards strings to LSL as String Markers

@author Sunny Fugate
"""
import argparse
import logging
import os
import multiprocessing
import queue
import signal
import socket
import sys
import threading
import time

from daemonize import Daemonize
from pylsl import StreamInfo, StreamOutlet, IRREGULAR_RATE

global process_logger
global data_logger
global is_daemon

UDP_IP = "127.0.0.1"
UDP_PORT = 1111
process_name = "LabStreamingLayer"
log_path = "/opt/cava-log/"
default_data_log = "lsl_data.json"


class UdpReceiver:

    def __init__(self, event_queue, ip, port):  # , interface):
        self.running = True
        self.event_queue = event_queue
        self.ip = ip
        self.port = port
        self.buffer_size = 4096 #This is a maximum, not the best solution, might still break on large fragmented data
        # self.address = socket.inet_aton(self.ip)
        # self.interface = interface
        self.datagram_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.datagram_socket.bind((self.ip, self.port))

    def ingest_data(self):
        process_logger.info("Waiting for data...")
        while self.running:
            try:
                # data, addr = self.socket.recvfrom(self.port)
                # TODO: fix the potential for larger packets to be fragmented and single packet to have truncated data
                data, _ = self.datagram_socket.recvfrom(self.buffer_size)

                # Blocking Queue with timeout
                self.event_queue.put(data, True, 5)
                process_logger.debug("Received data:"+str(data))
            except queue.Full:
                process_logger.info("Queue was full... memory limits too low?")

    def stop(self):
        self.running = False
        self.datagram_socket.close()


class LslStreamer:

    def __init__(self, event_queue, stream_name, stream_type, channel_count, sampling_rate, channel_format, source_id):
        self.running = True
        self.event_queue = event_queue
        self.stream_name = stream_name
        self.stream_type = stream_type
        self.channel_count = channel_count
        self.sampling_rate = sampling_rate
        self.channel_format = channel_format
        self.source_id = source_id

        # Create StreamInfo
        self.stream_info = StreamInfo(stream_name, stream_type, channel_count, sampling_rate, channel_format, source_id)

        # Create StreamOutlet
        self.outlet = StreamOutlet(self.stream_info)

    def expel_data(self):
        process_logger.info("Forwarding data to LSL...")

        while self.running:
            # TODO: add timeout and print exception?
            try:
                data = self.event_queue.get(True, 5)
                process_logger.debug("Sending data: "+str(data))
                json_str = data.decode('utf-8')
                self.outlet.push_sample([json_str])
                data_logger.info(json_str)
            except queue.Empty:
                process_logger.info("Output eventQueue is empty")

    def stop(self):
        self.running = False


class ServiceExit(Exception):
    """ Simple except for exiting threads """
    pass


def signal_handler(sig, frame):
    # def signal_handler(sig, frame):
    process_logger.info('Caught SIGINT / SIGTERM, exiting')
    raise ServiceExit


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create our shared event queue
    event_queue = multiprocessing.Queue()
    # TODO: include parameters

    receiver = UdpReceiver(event_queue, UDP_IP, UDP_PORT)

    streamer = LslStreamer(event_queue, 'GhidraEventMarkerStream', 'Markers', 1, IRREGULAR_RATE, 'string', 'ghidra')

    try:

        send = threading.Thread(name='sender', target=streamer.expel_data)
        recv = threading.Thread(name='receiver', target=receiver.ingest_data)

        process_logger.info("Starting Receiver Thread")
        recv.start()

        process_logger.info("Starting Streamer Thread")
        send.start()

        while True:
            time.sleep(0.5)
            pass

        # TODO: restart these if they crash?

    except ServiceExit:
        receiver.stop()
        streamer.stop()
        # TODO: close socket file descriptor with socket.close()?
        pass

    process_logger.info("Exiting program")


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
