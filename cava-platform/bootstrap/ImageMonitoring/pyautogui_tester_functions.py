import pyautogui, os, json, time, subprocess, sys
import unittest
#Now that we know where our python program is, let's import the functions needed to run.
if(os.path.isdir("/vagrant")):
	script_directory = "/opt/cava/"
else:
	script_directory = os.path.dirname(os.path.abspath(__file__)) + "/"

sys.path.insert(0, script_directory)   #This line lets us see option_data_functions from anywhere.
from ghidra_components import *
from ghidra_logger import *
from ghidra_action_monitor import *
'''
Functions file for running unit tests. Utilizes pyautogui to control the mouse and generate events.
@author Jeremy Johnson
'''
class ListenerClass():
	running = True
	#Initialize the global variables in "ghidra_action_monitor". This helps with logging and enables us to verify them.
	def __init__(self, ghidra_locations, event_queue, RELEASE):
		set_global_vars(ghidra_locations, event_queue, RELEASE)
	#Runs the listener for mouse events until it is told to stop.
	def run_listener(self):
		listener = Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll)
		listener.start()
		while(self.running):
			time.sleep(1)
		listener.stop()
	#Stop the listener here.
	def stop_listener(self):
		self.running = False

def kill_running_instrumentation(RELEASE):
	time.sleep(1)
	print("[KILLING PYTHON INSTRUMENTATION PROCESSES]")
	processes = subprocess.check_output("ps -ef | grep ghidra_action_monitor.py",shell=True).decode()
	processes = processes.split('\n')
	for process in processes:
		if("python3" in process and "ghidra_action_monitor.py" in process):
			process = process.split(" ")
			#This may vary based on OS, tested on vagrant and ubuntu 20.04
			if(RELEASE):
				pid = process[6]
				cmd = "sudo kill -9 " + str(pid)
			else:
				pid = process[5]
				cmd = "kill -9 " + str(pid)
			print(cmd)
			os.system(cmd)

def get_log_file_contents(log_path):
	if(os.path.isfile(log_path)):
		with open(log_path, "r") as f:
			all_lines = f.readlines()
	else:
		return []
	current_content = []
	for line in all_lines:
		try:
			json_line = json.loads(line)
		except:
			#Sometimes non-JSON data is put in this file during real use. Skip over that stuff!
			continue
		current_content.append(json_line)
	return current_content

def create_window_event_tests(all_windows):
	all_tests = {}
	for window_name in all_windows:
		all_tests[window_name] = {"ScrollUp": 0, "ScrollDown": 0, "RightClick": 0, "LeftClick": 0, "MouseEntry": 0, "MouseExit": 0, "BlockEvent": 0}
	return all_tests

def create_header_event_tests():
	all_headers = ["file", "edit", "analysis", "graph", "navigation", "search", "select", "tools", "window", "help"]
	all_tests = {}
	for header in all_headers:
		all_tests[header] = {"LeftClick": 0, "MouseEntry": 0, "MouseExit": 0, "drop down clicked": [], "sub menu clicked": []}
	return all_tests

def display_known_coordinates(coordinates):
	found_coords = []
	missing_coords = []
	total_possible_coords = len(coordinates)
	coordinates_discovered = 0
	for window_name in coordinates:
		if(coordinates[window_name][0][0] != -1):
			coordinates_discovered += 1
			found_coords.append(window_name)
		else:
			missing_coords.append(window_name)
	print("[VERIFY MANUALLY] Found: " + str(coordinates_discovered) + " | Total Possible: " + str(total_possible_coords))
	print("\tFound Coordinates:")
	for name in found_coords:
		print("\t\t-> " + str(name))
	print("\tMissing Coordinates: ")
	for name in missing_coords:
		print("\t\t-> " + str(name))
	if("FunctionGraph" in missing_coords):
		print("\n[NOTE] FunctionGraph is in missing coordinates. If it is present on the ghidra GUI, make sure an actual graph is loaded.\n")
	return found_coords, missing_coords



def perform_window_event_tests(found_coords, coordinates):
	print("[PERFORMING WINDOW EVENT TESTS]")
	print(found_coords)
	if("DisplayListing" in found_coords and "FunctionGraph" in found_coords):
		'''
		The goal here is to render something in the function graph. This is not as trivial as hitting "G" on a known location as 
		I have no guarantee on what binary will be open. I have opted to use the listing view to click a random location in the 
		binary and generate a function graph.
		'''
		#First get top right of the listing view
		x_coord = coordinates["DisplayListing"][1][0] - 26
		y_coord = (coordinates["DisplayListing"][0][1] + coordinates["DisplayListing"][1][1])/2
		pyautogui.moveTo(x_coord, y_coord, duration=1)
		pyautogui.mouseDown()
		time.sleep(5.3)
		pyautogui.mouseUp()
		#Overwrite the x_coord to be the middle of the listing view
		x_coord = (coordinates["DisplayListing"][0][0] + coordinates["DisplayListing"][1][0])/2
		pyautogui.click(x_coord, y_coord, button="left")
		#Depending on where we click, it may take a moment to load the graph.
		time.sleep(2)
		x_coord = (coordinates["FunctionGraph"][0][0] + coordinates["FunctionGraph"][1][0])/2
		y_coord = (coordinates["FunctionGraph"][0][1] + coordinates["FunctionGraph"][1][1])/2
		pyautogui.moveTo(x_coord, y_coord, duration=1)
		counter = 0
		while(counter < 70):
			pyautogui.scroll(1)
			counter += 1
			time.sleep(.01)
		#In a perfect world we are now showing the function graph blocks at max zoom. Wait two seconds to ensure the code captures the coordinates.
		time.sleep(2)
	else:
		print("\n[NOTE] Failed to test Function Graph Blocks. Either function graph or the listing view is not visible.")

	prev_coords = [-1,-1]
	#Loop through all coordinates, move mouse there, left/right click, scroll, sleep, repeat.
	for window_name in found_coords:
		window_coordinates = coordinates[window_name]
		x_coord = (window_coordinates[0][0] + window_coordinates[1][0])/2
		y_coord = (window_coordinates[0][1] + window_coordinates[1][1])/2
		pyautogui.moveTo(x_coord, y_coord, duration=1)
		pyautogui.click(x_coord, y_coord, button="right")
		time.sleep(.2)
		pyautogui.click(x_coord-2, y_coord-2, button="left")
		time.sleep(.2)
		pyautogui.scroll(-1)
		time.sleep(.1)
		pyautogui.scroll(1)
		time.sleep(.1)
		if(prev_coords[0] != -1):
			pyautogui.moveTo(prev_coords[0], prev_coords[1], duration=.3)
			time.sleep(.1)
		prev_coords = [x_coord, y_coord]

def get_window_event_test_results(test_results, log_path):
	file_contents = get_log_file_contents(log_path)
	for log_entry in file_contents:
		event_type = list(log_entry.keys())[0]
		if(event_type == "BlockCoordinateEvent"):
			if(len(log_entry[event_type]["Coordinates"]) > 0):
				test_results["FunctionGraph"]["BlockEvent"] += 1
			continue
		if("WindowName" not in log_entry[event_type] or (event_type != "WindowEvent" and event_type != "ScrollEvent")):
			continue
		window_name = log_entry[event_type]["WindowName"]
		#if(window_name in test_results):
		if(log_entry[event_type]["EventType"] in test_results[window_name]):
			test_results[window_name][log_entry[event_type]["EventType"]] += 1
	return test_results

def get_header_test_results(header_tests, log_path):
	file_contents = get_log_file_contents(log_path)
	for log_entry in file_contents:
		event_type = list(log_entry.keys())[0]
		if("Header" not in log_entry[event_type] or event_type != "HeaderEvent"):
			continue
		header_name = log_entry[event_type]["Header"]
		menu_item = log_entry[event_type]["MenuItem"]
		sub_menu_item = log_entry[event_type]["SubMenuItem"]
		header_event = log_entry[event_type]["EventType"]
		if(sub_menu_item != None):
			header_tests[header_name]["sub menu clicked"].append(sub_menu_item)
			header_tests[header_name]["drop down clicked"].append(menu_item)
		elif(menu_item != None):
			header_tests[header_name]["drop down clicked"].append(menu_item)
		if(header_event == "LeftClick" or header_event == "MouseEntry" or header_event == "MouseExit"):
			header_tests[header_name][header_event] += 1
	return header_tests

def perform_header_event_tests(ghidra_locations):
	print("[PERFORMING GHIDRA MENU TESTS]")
	ghidra_header_coords = ghidra_locations.get_header_locations()
	ghidra_sub_menu_coords = ghidra_locations.get_header_sub_drop_down_locations()	
	ghidra_menu_widths = ghidra_locations.get_header_menu_widths()
	ghidra_submenu_widths = ghidra_locations.get_header_sub_menu_widths()
	y_coord = (ghidra_header_coords["upper coord"] + ghidra_header_coords["lower coord"])/2
	#First test is going through all headers and clicking on them, double checking that it populates.
	for drop_down_name in ghidra_header_coords:
		if(drop_down_name == "upper coord" or drop_down_name == "lower coord"):
			continue
		down_down_x = (ghidra_header_coords[drop_down_name][0] + ghidra_header_coords[drop_down_name][1])/2
		pyautogui.moveTo(down_down_x, y_coord, duration=.4)
		pyautogui.click(down_down_x, y_coord, button="left")
		time.sleep(.2)
		pyautogui.click(down_down_x, y_coord, button="left")
	file_x_coord = (ghidra_header_coords["file"][0] + ghidra_header_coords["file"][1])/2
	help_x_coord = (ghidra_header_coords["help"][0] + ghidra_header_coords["help"][1])/2
	#Coordinates needed for selecting "data" in the "select" menu drop down
	select_x_coord = (ghidra_header_coords["select"][0] + ghidra_header_coords["select"][1])/2
	select_data_x_left = ghidra_header_coords["select"][0] + 1
	select_data_x_right = ghidra_menu_widths["select"]
	select_data_x_coord = select_data_x_left + select_data_x_right/2
	select_y_coords = ghidra_locations.get_header_drop_down_locations("select")
	select_data_y_coord = (select_y_coords[15][0] + select_y_coords[15][1])/2
	#Coordinates for selecting "graph export" in the sub menu.
	graph_x_coord = (ghidra_header_coords["graph"][0] + ghidra_header_coords["graph"][1])/2
	graph_data_x_left = ghidra_header_coords["graph"][0] + 1
	graph_data_x_right = ghidra_menu_widths["graph"]
	graph_data_x_coord = graph_data_x_left + graph_data_x_right/2
	graph_y_coords = ghidra_locations.get_header_drop_down_locations("graph")
	graph_output_y_coord = (graph_y_coords[7][0] + graph_y_coords[7][1])/2
	#Now the sub menu..
	graph_submenu_y_coords = ghidra_sub_menu_coords["GraphOutput"]
	graph_submenu_y_coord = (graph_submenu_y_coords[1][0] + graph_submenu_y_coords[1][1])/2
	graph_submenu_width = ghidra_submenu_widths["graph"]["GraphOutput"]
	graph_submenu_x_coord = graph_data_x_left + graph_data_x_right + 2 + graph_submenu_width/2
	#First test mouse hover functionality, from "file" over to "help"
	pyautogui.moveTo(file_x_coord, y_coord, duration=1)
	pyautogui.click(file_x_coord, y_coord, button="left")
	time.sleep(.2)
	pyautogui.moveTo(help_x_coord, y_coord, duration=1)
	pyautogui.moveTo(file_x_coord, y_coord, duration=1)
	pyautogui.click(file_x_coord, y_coord, button="left")
	time.sleep(.2)
	#Now go to "select", click it, move down to "data", and click!
	pyautogui.moveTo(select_x_coord, y_coord, duration=1)
	pyautogui.click(select_x_coord, y_coord, button="left")
	time.sleep(.2)
	#Move down and THEN over to the right to be extra sure we don't hover over a different menu and screw it all up.
	pyautogui.moveTo(select_x_coord, select_data_y_coord, duration=1)
	pyautogui.moveTo(select_data_x_coord, select_data_y_coord, duration=.5)
	pyautogui.click(select_data_x_coord, select_data_y_coord, button="left")
	time.sleep(.2)
	#Now for the "Graph export" sub menu item.
	pyautogui.moveTo(graph_x_coord, y_coord, duration=1)
	pyautogui.click(graph_x_coord, y_coord, button="left")
	time.sleep(.2)
	#Move down and THEN over to the right to be extra sure we don't hover over a different menu and screw it all up.
	pyautogui.moveTo(graph_x_coord, graph_output_y_coord, duration=1)
	pyautogui.moveTo(graph_data_x_coord, graph_output_y_coord, duration=.5)
	pyautogui.moveTo(graph_submenu_x_coord, graph_output_y_coord, duration=1)
	pyautogui.moveTo(graph_submenu_x_coord, graph_submenu_y_coord, duration=.5)
	pyautogui.click(graph_submenu_x_coord, graph_submenu_y_coord, button="left")


class GhidraInstrumentationTests(unittest.TestCase):
	log_path = -1
	windows_found = -1
	window_test_results = -1
	header_test_results = -1
	#The next 9 of 19 functions are for windows. They verify clicks, scrolls, and mouse entries/exits.
	def test_window_program_tree(self):
		if("ProgramTrees" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["ProgramTrees"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["ProgramTrees"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["ProgramTrees"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["ProgramTrees"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["ProgramTrees"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["ProgramTrees"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["ProgramTrees"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["ProgramTrees"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["ProgramTrees"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["ProgramTrees"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["ProgramTrees"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["ProgramTrees"]["MouseExit"])

	def test_window_function_graph(self):
		if("FunctionGraph" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["MouseExit"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["FunctionGraph"]["BlockEvent"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["MouseExit"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["FunctionGraph"]["BlockEvent"])				

	def test_window_task_survey(self):
		if("TaskSurvey" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskSurvey"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskSurvey"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskSurvey"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskSurvey"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskSurvey"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskSurvey"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskSurvey"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskSurvey"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskSurvey"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskSurvey"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskSurvey"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskSurvey"]["MouseExit"])	

	def test_window_defined_strings(self):
		if("DefinedStrings" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DefinedStrings"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DefinedStrings"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DefinedStrings"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DefinedStrings"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DefinedStrings"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DefinedStrings"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DefinedStrings"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DefinedStrings"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DefinedStrings"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DefinedStrings"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DefinedStrings"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DefinedStrings"]["MouseExit"])	

	def test_window_symbol_tree(self):
		if("SymbolTree" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["SymbolTree"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["SymbolTree"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["SymbolTree"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["SymbolTree"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["SymbolTree"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["SymbolTree"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["SymbolTree"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["SymbolTree"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["SymbolTree"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["SymbolTree"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["SymbolTree"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["SymbolTree"]["MouseExit"])	

	def test_window_data_type_manager(self):
		if("DataTypeManager" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DataTypeManager"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DataTypeManager"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DataTypeManager"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DataTypeManager"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DataTypeManager"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DataTypeManager"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DataTypeManager"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DataTypeManager"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DataTypeManager"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DataTypeManager"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DataTypeManager"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DataTypeManager"]["MouseExit"])	

	def test_window_decompiler(self):
		if("Decompiler" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["Decompiler"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["Decompiler"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["Decompiler"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["Decompiler"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["Decompiler"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["Decompiler"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["Decompiler"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["Decompiler"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["Decompiler"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["Decompiler"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["Decompiler"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["Decompiler"]["MouseExit"])	

	def test_window_display_listing(self):
		if("DisplayListing" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DisplayListing"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DisplayListing"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DisplayListing"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DisplayListing"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DisplayListing"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["DisplayListing"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DisplayListing"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DisplayListing"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DisplayListing"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DisplayListing"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DisplayListing"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["DisplayListing"]["MouseExit"])	

	def test_window_task_instructions(self):
		if("TaskInstructions" in self.windows_found):
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskInstructions"]["ScrollUp"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskInstructions"]["ScrollDown"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskInstructions"]["RightClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskInstructions"]["LeftClick"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskInstructions"]["MouseEntry"])
			with self.subTest():
				self.assertNotEqual(0, self.window_test_results["TaskInstructions"]["MouseExit"])
		else:
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskInstructions"]["ScrollUp"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskInstructions"]["ScrollDown"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskInstructions"]["RightClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskInstructions"]["LeftClick"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskInstructions"]["MouseEntry"])
			with self.subTest():
				self.assertEqual(0, self.window_test_results["TaskInstructions"]["MouseExit"])	

	#The final 10 tests below are for headers. We verify left clicks, hovers, drop downs and sub menu clicks.
	def test_header_file(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["file"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["file"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["file"]["MouseExit"])
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["file"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["file"]["sub menu clicked"]))

	def test_header_edit(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["edit"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["edit"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["edit"]["MouseExit"])
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["edit"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["edit"]["sub menu clicked"]))

	def test_header_analysis(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["analysis"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["analysis"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["analysis"]["MouseExit"])			
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["analysis"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["analysis"]["sub menu clicked"]))

	def test_header_graph(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["graph"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["graph"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["graph"]["MouseExit"])			
		with self.subTest():
			self.assertNotEqual(0, len(self.header_test_results["graph"]["drop down clicked"]))
		with self.subTest():
			self.assertNotEqual(0, len(self.header_test_results["graph"]["sub menu clicked"]))


	def test_header_navigation(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["navigation"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["navigation"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["navigation"]["MouseExit"])			
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["navigation"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["navigation"]["sub menu clicked"]))

	def test_header_search(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["search"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["search"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["search"]["MouseExit"])			
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["search"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["search"]["sub menu clicked"]))

	def test_header_select(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["select"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["select"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["select"]["MouseExit"])			
		with self.subTest():
			self.assertNotEqual(0, len(self.header_test_results["select"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["select"]["sub menu clicked"]))

	def test_header_tools(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["tools"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["tools"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["tools"]["MouseExit"])			
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["tools"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["tools"]["sub menu clicked"]))

	def test_header_window(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["window"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["window"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["window"]["MouseExit"])			
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["window"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["window"]["sub menu clicked"]))

	def test_header_help(self):
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["help"]["LeftClick"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["help"]["MouseEntry"])
		with self.subTest():
			self.assertNotEqual(0, self.header_test_results["help"]["MouseExit"])			
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["help"]["drop down clicked"]))
		with self.subTest():
			self.assertEqual(0, len(self.header_test_results["help"]["sub menu clicked"]))
