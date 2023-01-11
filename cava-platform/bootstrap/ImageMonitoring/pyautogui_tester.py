from pyautogui_tester_functions import *
pyautogui.FAILSAFE = True


global RELEASE
log_file_name = "GhidraClickLogs.log"
#To run locally, set this to False. To run on Vagrant VM, set it to True and execute "vagrant up --provision"
if(os.path.isdir("/vagrant")):
	#Eventually we will change these paths to something that works with vagrant.
	log_path = "/opt/cava-log/" + log_file_name
	RELEASE = True
else:
	log_path = os.path.dirname(os.path.abspath(__file__)) + "/" + log_file_name
	RELEASE = False
'''
Controller for the unit tester. Starts all threads and initializes all classes for running tests.
Then verifies output generated.
@author Jeremy Johnson
'''
def main():
	output_string = """
	\tPython External Instrumentation Testing!\n\t\t\t    Version 1.0.1\n\n
	==== MOVE MOUSE TO TOP LEFT TO IMMEDIATELY STOP TESTING ====


	Tests To Run:
	-- Set Up --
	1) Delete existing log files
	2) Kill any other python instrumentation running on the system
	-- Window Events --
	3) Go through all known windows and enter/exit them, left and right click, scroll up and down.
	-- Header Events --
	4) Click on each menu option individually
	5) Click on "File", hover over all headers, then click on "Help" to cancel the hovering functionality.
	6) Click on the drop down item in select -> data.
	7) Click on the sub menu item in graph -> graph output -> graph export

	Wait a few moments to get results and close down the processes.

	"""
	print(output_string)
	#FIRST: Delete the log file so we know we are starting with a fresh file.
	if(os.path.isfile(log_path)):
		print("Deleting Existing Log File.")
		os.system("rm " + str(log_path))
	#SECOND: Kill and then start the ghidra_action_monitor.py program if it is not already running. Need to do this for the log file.
	kill_running_instrumentation(RELEASE)
	
	event_queue = multiprocessing.Queue()
	#The big three for running python instrumentation.
	ghidra_locations = ghidra_windows(RELEASE)
	event_logger = EventLogger(event_queue, __file__, log_path)
	ghidra_monitor = monitor_ghidra_borders(ghidra_locations, event_queue)
	graph_block_monitor = monitor_graph_blocks(ghidra_locations, event_queue)

	#Get the coordinates
	ghidra_monitor.ghidra_reposition_check()
	#Use the classes "getters" to pull relevant information
	ghidra_coordinates = ghidra_locations.get_ghidra_window_coordinates()

	windows_found, windows_missing = display_known_coordinates(ghidra_coordinates)
	all_windows = windows_found + windows_missing
	#Log events as they happen to a file.
	lsl_logging_thread = threading.Thread(name='event_logger', target=event_logger.expel_and_log_data)
	lsl_logging_thread.start()
	#This is a special class. It activates on mouse events and executes the code necessary for logs to happen.
	listener_class = ListenerClass(ghidra_locations, event_queue, RELEASE)
	keylogger = threading.Thread(name='keylogger', target=listener_class.run_listener)
	keylogger.start()
	graph_block_monitor_thread = threading.Thread(name='graph_blocks', target=graph_block_monitor.monitor_ghidra_graph_blocks)
	graph_block_monitor_thread.start()

	#############################################
	perform_window_event_tests(windows_found, ghidra_coordinates)
	#Create the test data structure that needs to be populated with log events
	test_results = create_window_event_tests(all_windows)
	window_test_results = get_window_event_test_results(test_results, log_path)
	
	perform_header_event_tests(ghidra_locations)
	header_tests = create_header_event_tests()
	header_test_results = get_header_test_results(header_tests, log_path)

	print("\n[TESTS COMPLETED] Shutting Threads Down...")
	event_logger.stop()
	listener_class.stop_listener()
	graph_block_monitor.stop()
	print("\n[VERIFYING RESULTS]")
	#NOTE: Everything up to this point is initialization for the tests and running them.
	#		- What I do below is technically "bad practice", but my tests need access to the test results!! 
	#		  I don't want to re-compute the coordinates for each test when I assume no one is touching ghidra.
	#		  So with that in mind I update class variables so they're available to each test.
	GhidraInstrumentationTests.log_path = log_path
	GhidraInstrumentationTests.windows_found = windows_found
	GhidraInstrumentationTests.window_test_results = window_test_results
	GhidraInstrumentationTests.header_test_results = header_test_results
	unittest.main()
	
if __name__ == '__main__':
	main()




