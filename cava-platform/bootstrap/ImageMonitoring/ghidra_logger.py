import logging, json
import queue
import multiprocessing, socket
#Hard coded IP and PORT for sending UDP data.
UDP_IP = "127.0.0.1"
UDP_PORT = 1111

'''
class: EventLogger
Functionality:
	- As the program is running we have events to record to the lab streaming layer
	- This is run in a thread, so it all happens asynchronously with out interrupting the mouse monitor code.
@author Jeremy Johnson
'''
class EventLogger:
	#sets up the queue and logger
	def __init__(self, event_queue, logger_name, log_file):
		self.running = True
		self.event_queue = event_queue
		#Socket for sending data.
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		#Create logger for the header monitoring.
		self.data_logger = self.setup_logger(logger_name, log_file)

	def setup_logger(self, name, log_file):
		data_logger = logging.getLogger(name)
		data_logger.setLevel(logging.INFO)
		file_handler = logging.FileHandler(log_file)
		data_logger.addHandler(file_handler)
		return data_logger
	#This function is run in a thread, waiting for the event queue to be populated.
	def expel_and_log_data(self):
		while self.running:
			try:
				json_str = self.event_queue.get(True, 5) ### Blocking == True, timeout == 5 seconds.
				#Send the json data via UDP and log locally to a file.
				self.sock.sendto(json_str.encode('utf-8'), (UDP_IP, UDP_PORT))
				self.data_logger.info(json_str)
			except queue.Empty:
				pass

	def stop(self):
		self.running = False

