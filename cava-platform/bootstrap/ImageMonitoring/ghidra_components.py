import time
from pynput.mouse import Listener
import numpy as np
import cv2 as cv
import mss
from PIL import Image
import os, json
from multiprocessing import Pool
##NOTE: There is a bug in tesserocr code. This is known in the library and this is an "official" temporary fix.
import locale
locale.setlocale(locale.LC_ALL, 'C')
import tesserocr

'''
Class: ghidra_windows

This class handles the locations of all items in ghidra that we are interested in. It uses
openCV and numpy to identify images on the screen and pools to efficiently find them. This can support 
pretty much any item or overlay in ghidra as needed. It struggles when drop downs or items
are not consistent and we don't know what to look for.

Current functionality supports the headers in ghidra and their drop downs. The menus and
sub menus distance have been identified and are pixel-perfect accurate.

We can also find the following 7 windows on the ghidra GUI:
DisplayListing, SymbolTree, TaskInstructions, DataTypeManager, Decompiler, ProgramTrees, FunctionGraph

The code assumes we have found all "X" marks on the screen, uses them to correlate which bottom right
item is correct for the window.

@author Jeremy Johnson
'''
class ghidra_windows:
	base_path = os.path.dirname(os.path.abspath(__file__))
	path_to_images = base_path + "/images/"
	function_graph_images = ["function_graph_gray.png", "function_graph_selected.png"]
	x_mark_image = "X_mark.png"
	down_arrow_image = "down_arrow.png"
	header_window_image = "header_window_image.png"
	selected_header_window_image = "header_window_image_clicked.png"

	#When the header is found, this contains coordinates for all of them.
	header_locations = {}
	#This dict keeps track of the header boundaries in each drop down.
	header_drop_down_locations = {}
	#This dict keeps track of the header sub drop down boundaries
	header_sub_drop_down_locations = {}
	#This is a dict with value being a list, each key is the header name with the value sub drop down entry, followed by its index in the menu
	sub_drop_downs = {"File": [["Export", 19]], "Analysis": [["OneShot", 2]], "Graph": [["CallsUsingModel", 3],["Data", 4],["GraphOutput", 8]],
					  "Search": [["ForMatchingInstructions", 5]], "Select": [["ProgramHighlight", 9], ["ScopedFlow", 10]]}
	#This variable tells me which header item has been clicked, if any.
	header_focused = ""
	#This stores the width of the drop down box after it has been clicked.
	header_drop_down_right_X = 0
	#When the menu is being hovered and the mouse crosses the (X->X+19 & Y pixel) threshold to go into the sub menu, this is populated.
	drop_down_name = ""
	#Dictionary, key is the name of view, value is the coordinates of the view.
	all_ghidra_window_coords = {}
	#Dictionary, key is the name of the block, value is the coordinates of the block.
	function_graph_block_coords = {}	
	#When the mouse is hovering over ghidra windows this is set as it goes from one to the other.
	current_ghidra_window = ""
	time_in_ghidra_window = -1
	#When the mouse is hovering over ghidra headers we track its name and time in it.
	current_ghidra_header = ""
	header_entry_time = -1
	#When the mouse is hovering over ghidra header drop downs we track its name and time in it.
	current_ghidra_drop_down = ""
	time_in_header_drop_down = -1
	#When the mouse is hovering over ghidra header sub menus we track its name and time in it.
	current_ghidra_sub_menu = ""
	time_in_header_sub_menu = -1
	#The last window that was clicked will have focus on it. I will be recording that in this variable.
	focused_window = ""
	#Boolean for helping with prints
	RELEASE = False
	def __init__(self, release_flag):
		self.RELEASE = release_flag

	#This takes a screen grab and saves the bytes in memory.
	def get_screen_shot_bytes(self):
		with mss.mss() as sct:
			#sct.monitors will show information on the whole monitor setup.
			sct_img = sct.grab(sct.monitors[0]) #[0] gives me the whole screen realestate. [1] gives first screen, etc.
			img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
			return img
	
	'''
	Function: find_all_X_marks
	Input:
		monitor_bytes - These are the bytes from the function get_screen_shot_bytes of the current monitor.
	Functionality:
		Using the screen shot we search for all occurrences of the "X" mark on the screen. These coordinates are used
		in the pool function later.
	Returns:
		A 2-d list with all the coordinates of the "X" icons. Just provides the x,y coordinates, not the whole image area.
	'''
	def find_all_X_marks(self, monitor_bytes):
		full_listing_path = self.path_to_images + self.x_mark_image
		image = cv.imread(full_listing_path)
		_, image_width, image_height = image.shape[::-1]
		img_cv = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
		result = cv.matchTemplate(img_cv, image, cv.TM_CCOEFF_NORMED)
		#The openCV pattern match I used returns a 2-d matrix, where likely locations are >= .9 in value.
		loc = np.where(result>=.9)
		#Note: "Window" was chosen for being unique. So this loop will only execute once.
		all_X_coords = []
		for coordinate in zip(*loc[::-1]):
			X_coordinates = [coordinate[0], coordinate[1]]
			all_X_coords.append(X_coordinates)
		return all_X_coords

	def find_all_graph_marks(self, monitor_bytes, paths):
		full_listing_path = self.path_to_images + "graph_block_top_right_max_zoom.png"
		full_listing_path = self.path_to_images + "graph_block_top_right_not_max.png"
		image = cv.imread(full_listing_path)
		_, image_width, image_height = image.shape[::-1]
		img_cv = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
		result = cv.matchTemplate(img_cv, image, cv.TM_CCOEFF_NORMED)
		#The openCV pattern match I used returns a 2-d matrix, where likely locations are >= .9 in value.
		loc = np.where(result>=.9)
		#Note: "Window" was chosen for being unique. So this loop will only execute once.
		all_X_coords = []
		for coordinate in zip(*loc[::-1]):
			X_coordinates = [coordinate[0], coordinate[1]]
			all_X_coords.append(X_coordinates)
		return all_X_coords

	'''
	Function: find_all_sub_images
	Input:
		image_paths - These are the paths that we use for the sub images.
		monitor_bytes - These are the bytes from the function get_screen_shot_bytes of the current monitor.
		image_counter - This is the image that we will start on.
	Functionality:
		Using the screen shot we search for the sub images inside the monitor bytes.

		The first sub image that returns locations causes us to stop. This means the order you pass in the image_paths matters.
		I chose this because this function is used for finding unique and non-unique items. In the event of a unique image
		being found, we don't want to return additional noise with it.

		The bottom right tends to not be unique and we may get false positives that don't line up with our "X" mark. When
		this happens we can try again with a different image, the "image_counter" variable allows us to not repeat images.
	Returns:
		A 2-d list with all the coordinates sub image locations.
		The next image that would be started on should this function be called again.
	'''	
	def find_all_sub_images(self, image_paths, monitor_bytes, image_counter):
		all_coords = {}
		all_coords["coordinates"] = []
		all_coords["height"] = -1
		all_coords["width"] = -1
		while(image_counter < len(image_paths)):
			image_path = image_paths[image_counter]
			#Slightly unconventional counter increase location here. If we break it needs to have been updated.
			image_counter += 1
			image = cv.imread(image_path)
			_, image_width, image_height = image.shape[::-1]
			#Note: We may check multiple images, they will all (more or less) have the same width / height.
			all_coords["width"] = image_width
			all_coords["height"] = image_height
			img_cv = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
			result = cv.matchTemplate(img_cv, image, cv.TM_CCOEFF_NORMED)
			#The openCV pattern match I used returns a 2-d matrix, where likely locations are >= .9 in value.
			loc = np.where(result>=.9)
			#Note: "Window" was chosen for being unique. So this loop will only execute once.
			for coordinate in zip(*loc[::-1]):
				#print(image_path) ## Useful for testing individual images.
				all_coords["coordinates"].append([coordinate[0], coordinate[1]])
			#There are times I use multiple images, if one finds an image that should be the one! No need to do the next one.
			if(len(all_coords["coordinates"]) > 0):
				break
		return all_coords, image_counter

	def find_corresponding_X_coordinate(self, top_left_X, top_left_Y, all_X_coords):
		top_right_X = -1
		top_right_Y = -1
		#print("X|Y: " + str(top_left_X) + ", " + str(top_left_Y))
		for coordinates in all_X_coords:
			#Check the Y coordinate to make sure I am on the right plane.
			#print(coordinates[1])
			if(top_left_Y - 7 < coordinates[1] and top_left_Y + 7 > coordinates[1]):
				#If the "listing" image was found on the left, this is a potential match!
				if(top_left_X < coordinates[0]):
					#Two cases, top_right could be -1 or it could be set. I am looking for the CLOSEST X to the listing image.
					if(top_right_X == -1):
						top_right_X = coordinates[0]
						top_right_Y = coordinates[1]
					else:
						if(coordinates[0] < top_right_X):
							top_right_X = coordinates[0]
							top_right_Y = coordinates[1]
		return top_right_X, top_right_Y

	'''
	Function: find_ghidra_view_coordinates
	Input: input_arguments - a dictionary with the following keys:
		"monitor bytes" - The bytes of the monitors
		"X coordinates" - The coordinates of all "X" marks from the ghidra GUI
		"window name" - The name of the window that we are looking for.
		"paths" - The paths to images that will be used to find the windows coordinates. This is a 2-d list.
	Functionality: 
		The bytes for the monitor and the X mark locations have been previously found. This function is called from a pool
		and is re-used over and over again. In order to accomplish this with the pool I have streamlined the process
		of finding windows on the ghidra GUI.

		First I find the unique top left image of the window. Most windows have a unique icon. This icon can be 
		selected or grayed out. Always check for the grayed out icon first, as there can only be one selected entry 
		at once.

		I then determine which "X" mark corresponds to the unique top left coordinates I recovered. It will always be there, 
		and it will always be the closest to the right. 

		Lastly I find the bottom right coordinate. Up until this point I have the top Y coordinate and the left and right
		boundaries. The bottom right of most windows is easy to find. In most cases the bottom right is not unique, so I find
		the highest occurrence of the item that lines up vertically with the chosen "X" mark.

		However it is not always this simple, the bottom right corner can vary drastically by which window. The function graph has
		a small square in the botton right that is dockable for example. This pool function enables me to send in multiple images
		to search for, when it finds the image on the screen it does not check the following images. This makes the order of
		the images you send in extremely important. This can be seen most distinctly in the function graph, I first check for
		a unique image in the icon when the bottom right square is not showing. I then check for the image with the box, which 
		is always found 30+ times on the screen. If I did it in the other order we would get false positives and fail to find the
		window coordinates!

	Return Value:
		A 2-d list with the top left and bottom right coordinates. I must int() each item because they are numpy int64 objects and
		json does not know how to handle them as is.
	'''
	def find_ghidra_view_coordinates(self, input_arguments):
		monitor_bytes = input_arguments["monitor bytes"]
		all_X_coords = input_arguments["X coordinates"]
		window_name = input_arguments["window name"]
		top_left_image_paths = input_arguments["paths"][0]
		bottom_right_image_paths = input_arguments["paths"][1]
		#monitor_bytes, all_X_coords, window_name, top_left_image_paths, bottom_right_image_paths
		#The return value has the name of what it is for in it.
		output_data = {}
		output_data[window_name] = [[-1, -1], [-1, -1]]
		initial_image = 0
		top_left_location, image_counter = self.find_all_sub_images(top_left_image_paths, monitor_bytes, initial_image)
		if(top_left_location["coordinates"] == []):
			if(not self.RELEASE):
				print("Failed to find unique top left for " + str(window_name))
			return output_data
		#A 2-D list is returned, for this situation we get a unique field back with one entry.
		#print(str(top_left_location["coordinates"]) + " | " + str(window_name))
		if(window_name == "TaskSurvey"):
			#When it is being tested on the Vagrant VM but NOT in the platform mode, there are two ghidra images. One is in the top left, so it will always be first. This is not a problem in release mode.
			top_left_location = top_left_location["coordinates"][-1]
		else:
			top_left_location = top_left_location["coordinates"][0]
		#These coordinates are the top left point of the image. Should be a solid top / left boundary for the view.
		top_left_X = top_left_location[0]
		top_left_Y = top_left_location[1]
		if(window_name != "TaskSurvey"):
			top_right_X, top_right_Y = self.find_corresponding_X_coordinate(top_left_X, top_left_Y, all_X_coords)

			if(top_right_X == -1):
				if(not self.RELEASE):
					print("Failed to find top right X / Y locations of the " + str(window_name) + " view")
				return output_data
		else:
			task_survey_X_mark = [self.path_to_images + "task_survey_X_mark.png"]
			initial_image = 0
			top_right_X_location, image_counter = self.find_all_sub_images(task_survey_X_mark, monitor_bytes, initial_image)
			if(top_right_X_location["coordinates"] == []):
				if(not self.RELEASE):
					print("Failed to find unique top right X for TaskSurvey")
				return output_data
			top_right_locations = top_right_X_location["coordinates"][0]
			top_right_X = top_right_locations[0]
			top_right_Y = top_right_locations[1]

		image_counter = 0
		#This counter is incremented in "find_all_sub_images" automatically!
		while(image_counter < len(bottom_right_image_paths)):
			all_bot_right_coords, image_counter = self.find_all_sub_images(bottom_right_image_paths, monitor_bytes, image_counter)
			#I adjust the coordinates to the bottom right corner of the image. This is a more accurate pixel boundary for the right and bottom boundaries.
			img_height = all_bot_right_coords["height"]
			img_width = all_bot_right_coords["width"]
			bottom_right_X = -1
			bottom_right_Y = -1
			for coordinates in all_bot_right_coords["coordinates"]:
				#Check the X coordinate to make sure I am on the right line.
				if(top_right_X - 25 < coordinates[0] and top_right_X + 25 > coordinates[0]):
					#If the "X" image was found above the arrow, this is a potential match! Add 30 to the Y to make sure there is space and it isn't a false positive.
					if(top_right_Y + 30 < coordinates[1]):	
						#Two cases, top_right could be -1 or it could be set. I am looking for the CLOSEST X to the listing image.
						if(bottom_right_X == -1):
							bottom_right_X = top_right_X + 18
							bottom_right_Y = coordinates[1] + img_height
						else:
							if(coordinates[1] < top_right_Y):
								bottom_right_X = top_right_X + 18
								bottom_right_Y = coordinates[1] + img_height
			#If we found an image that lines up with the "X", assume that this is the right one!
			if(bottom_right_X != -1):
				break
			if(not self.RELEASE):
				print("Failed to find bottom right X / Y locations of the " + str(window_name) + " view")
		if(bottom_right_X == -1):
			return output_data
		#Each item MUST be wrapped in int(). These are numpy numbers that are int64 type, not JSON friendly.
		output_data[window_name] = [[int(top_left_X), int(top_left_Y)], [int(bottom_right_X), int(bottom_right_Y)]]
		return output_data

	'''
	Function: find_all_header_positions
	Input: N/A
	Functionality: 
		This function uses a previously taken screen shot of "Window" in the header and finds it on the screen.
		From this location, I find where "File" is, on the left. I use "Window" because it is unique.
			- From "File", I know the offsets from one header entry to the next. 
		Since drop down menus are static for each ghidra version, I compute the location of each menu drop down and
		sub-menu drop down immediately.
		
		All of these computed boundaries are saved in class variables accessible with getters.
	'''
	def find_all_header_positions(self):
		#The whole header is on a horizontal line, I need the upper and lower Y axis of this line.
		header_Y_upper = -1
		header_Y_lower = -1

		all_X_coords = []
		monitor_bytes = self.get_screen_shot_bytes()
		window_image = cv.imread(self.path_to_images + self.header_window_image)
		_, window_width, window_height = window_image.shape[::-1]
		img_cv = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
		result = cv.matchTemplate(img_cv, window_image, cv.TM_CCOEFF_NORMED)
		#The openCV pattern match I used returns a 2-d matrix, where likely locations are >= .9 in value.
		found_window_params = False
		loc = np.where(result>=.9)
		#Note: "Window" was chosen for being unique. So this loop will only execute once.
		for coordinate in zip(*loc[::-1]):
			found_window_params = True
			header_Y_upper = coordinate[1] + window_height
			header_Y_lower = coordinate[1]
			#Image is for "Window", move the X over to where "File" starts. Uses "Window" because it is unique.
			beginning_of_headers = coordinate[0] - 386
			file_header_X_start = beginning_of_headers + 1
		if(not found_window_params):
			#The first image check above is for the case where "Window" is not selected. If it is selected it will not be found.
			#We check for the case where it is selected here, ensuring we don't miss coordinates!
			window_image = cv.imread(self.path_to_images + self.selected_header_window_image)
			_, window_width, window_height = window_image.shape[::-1]
			img_cv = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
			result = cv.matchTemplate(img_cv, window_image, cv.TM_CCOEFF_NORMED)
			#The openCV pattern match I used returns a 2-d matrix, where likely locations are >= .9 in value.
			found_window_params = False
			loc = np.where(result>=.9)
			#Note: "Window" was chosen for being unique. So this loop will only execute once.
			for coordinate in zip(*loc[::-1]):
				found_window_params = True
				header_Y_upper = coordinate[1] + window_height
				header_Y_lower = coordinate[1]
				#Image is for "Window", move the X over to where "File" starts. Uses "Window" because it is unique.
				beginning_of_headers = coordinate[0] - 386
				file_header_X_start = beginning_of_headers + 1

			if(not found_window_params):
				if(not self.RELEASE):
					print("Failed to find 'Window' in ghidra menu, no menu coordinates available.")
				return
		self.header_locations["upper coord"] = header_Y_upper
		self.header_locations["lower coord"] = header_Y_lower
		#These offsets are always the same across multiple ghidra installations. So this should never be altered. All these are 1 pixel larger than actual size.
		file_distance = 29 
		edit_distance =  33
		analysis_distance = 59
		debugger_distance = 71
		graph_distance = 47
		navigation_distance = 75
		search_distance = 53
		select_distance = 47
		tools_distance = 41
		window_distance = 55
		help_distance = 37
		
		#Each of these follow the same pattern. They are pixel perfect X coordinates of the start/end of each header entry.
		file_header_ending = file_header_X_start + file_distance
		self.header_locations["File"] = [file_header_X_start + 1, file_header_ending]
		edit_header_ending = file_header_ending + edit_distance
		self.header_locations["Edit"] = [file_header_ending + 1, edit_header_ending]
		analysis_header_ending = edit_header_ending + analysis_distance
		self.header_locations["Analysis"] = [edit_header_ending + 1, analysis_header_ending]
		graph_header_ending = analysis_header_ending + graph_distance
		self.header_locations["Graph"] = [analysis_header_ending + 1, graph_header_ending]
		navigation_header_ending = graph_header_ending + navigation_distance
		self.header_locations["Navigation"] = [graph_header_ending + 1, navigation_header_ending]
		search_header_ending = navigation_header_ending + search_distance
		self.header_locations["Search"] = [navigation_header_ending + 1, search_header_ending]
		select_header_ending = search_header_ending + select_distance
		self.header_locations["Select"] = [search_header_ending + 1, select_header_ending]
		tools_header_ending = select_header_ending + tools_distance
		self.header_locations["Tools"] = [select_header_ending + 1, tools_header_ending]
		window_header_ending = tools_header_ending + window_distance
		self.header_locations["Window"] = [tools_header_ending + 1, window_header_ending]
		help_header_ending = window_header_ending + help_distance
		self.header_locations["Help"] = [window_header_ending + 1, help_header_ending]
		#I am able to pre-compute all dropdown locations when we start, easy access to them in "on_click" later.
		header_Y_starting_point = self.header_locations["upper coord"] + 6
		all_headers = ["File", "Edit", "Analysis", "Graph", "Navigation", "Search", "Select", "Tools", "Window", "Help"]
		for header in all_headers:
			drop_down_boundaries = self.create_drop_down_boundaries(header_Y_starting_point, header)
			self.header_drop_down_locations[header] = drop_down_boundaries
		#For each header drop down item that has a sub menu, we need to map out those locations as well.
		for header_name in self.sub_drop_downs:
			for drop_down_list in self.sub_drop_downs[header_name]:
				sub_drop_down = drop_down_list[0]
				drop_down_index = drop_down_list[1]
				#The sub menu first entry top Y is the top Y of the menu + 6 pixels. Same space from the header to the menu!
				sub_header_Y_starting_point = self.header_drop_down_locations[header_name][drop_down_index][0] + 6
				sub_drop_down_boundaries = self.create_sub_drop_down_boundaries(sub_header_Y_starting_point, header_name, sub_drop_down)
				self.header_sub_drop_down_locations[sub_drop_down] = sub_drop_down_boundaries

	#Given the coordinates of the top right of the task instructions window, I use OCR to find the time stamp in ghidra.
	def find_time_stamp(self, monitor_bytes, top_right_X, top_right_Y):
		cv_monitor_bytes = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
		#These offsets are specific to the image I took to create a close fit, but not *too* close otherwise we lose accuracy.
		y_coords = [top_right_Y + 24, top_right_Y + 38]
		x_coords = [top_right_X - 137, top_right_X + 11]
		cropped_image = cv_monitor_bytes[y_coords[0]: y_coords[1], x_coords[0]:x_coords[1]]

		api = tesserocr.PyTessBaseAPI()
		api.SetVariable('tessedit_char_whitelist', "1234567890.")
		api.SetImage(Image.fromarray(cropped_image))
		ocr_time_stamp = api.GetUTF8Text()
		#For some reason a new line is appended to the time stamp. While it is not clear why, it is easy enough to remove.
		if("\n" in ocr_time_stamp):
			ocr_time_stamp = ocr_time_stamp.replace("\n","")
		#Sometimes we get a "," instead of a ".". Also, sometimes we get ",." where a "." is expected. Some post processing fixes that:
		if(",." in ocr_time_stamp or ".," in ocr_time_stamp):
			ocr_time_stamp = ocr_time_stamp.replace(",","")
		elif("," in ocr_time_stamp):
			ocr_time_stamp = ocr_time_stamp.replace(",",".")
		return ocr_time_stamp


	'''
	Function: create_drop_down_boundaries
	Input: 
		- drop_down_starting_point: This is the Y coordinate of where the drop down starts (top of the drop down)
		- header_name: This is the name of the header that is in focus, aka the header that was clicked.
	Functionality: 
		- I have counted the number of items in each drop down from the header, each item is a fixed height
		  so I can compute the Y coordinates of where each item is.
		- There are occasionally horizontal lines in the drop downs, when clicked nothing happens. To account
		  for this I add 5 pixels between drop downs with a horizontal line between them. The code in event_listener
		  handles the logic for what to do based on the click location.
		- These are all computed right when we start, so it is ready immediately when a click happens with no extra work required.
	'''
	def create_drop_down_boundaries(self, drop_down_starting_point, header_name):
		#These define the number of sub entries in each drop down menu.
		drop_down_header_entries = {"File":22, "Edit":9, "Analysis":4, "Graph":9, "Navigation":16, "Search":11, 
									"Select":22, "Tools":3, "Window":29, "Help":6}
		#Each header may have horizontal lines in the drop down which add a few pixels. The inner dictionaries tell me where the lines are.
		drop_down_line_breaks = {"File": {5:1, 8:1, 12:1, 13:1, 14:1, 15:1, 17:1, 18:1, 21:1, 22:1},
								 "Edit": {5:1, 8:1}, "Analysis": {4:1}, "Graph": {4:1,6:1,9:1},
								 "Navigation": {4:1, 8:1, 11:1}, "Search": {2:1,6:1}, 
								 "Select": {9:1, 10:1, 11:1, 15:1, 19:1, 21:1}, "Tools": {1:1, 2:1},
								 "Window": {}, "Help": {4:1, 5:1, 6:1}}
		number_of_entries = drop_down_header_entries[header_name]
		horizontal_line_locations = drop_down_line_breaks[header_name]
		#Each item in a drop down is 19px tall, horizontal lines add 5px.
		drop_down_item_height = 19
		horizontal_bar_height = 5
		drop_down_Y_boundaries = [[drop_down_starting_point, drop_down_starting_point + drop_down_item_height]]
		drop_down_counter = 1
		while(drop_down_counter < number_of_entries):
			previous_drop_down_height = drop_down_Y_boundaries[drop_down_counter - 1][1]
			#When there is a line separating two items in the drop down, move the start down just a bit. +1 for zero offset fix.
			if(drop_down_counter+1 in horizontal_line_locations):
				previous_drop_down_height += horizontal_bar_height
			drop_down_Y_boundaries.append([previous_drop_down_height, previous_drop_down_height + drop_down_item_height])
			drop_down_counter += 1
		return drop_down_Y_boundaries
	'''
	Function: create_sub_drop_down_boundaries
	Input:
		- sub_drop_down_starting_point: This is where the sub-menu Y coordinate starts, derived from the menu item upper boundary
		- header_name: This is the name of the header that is in focus, aka the header that was clicked.
		- menu_item_name: The menu item name that was hovered over is used to figure out how many sub-menu drop downs there are.
	Functionality: 
		- This is basically the same as create_drop_down_boundaries(), however it is for sub-menus. 
		- I also don't have to worry about horizontal lines here.
	'''
	def create_sub_drop_down_boundaries(self, sub_drop_down_starting_point, header_name, menu_item_name):
		sub_drop_down_header_entries = {"File": {"Export": 2}, "Analysis": {"OneShot":15}, "Graph":{"CallsUsingModel":4, "Data":3,
										"GraphOutput": 2}, "Search": {"ForMatchingInstructions": 3}, 
										"Select":{"ProgramHighlight": 4, "ScopedFlow": 2}}
		#NOTE: There are no horizontal entries in sub menus at this point in time. Logic changes would need to be made here.
		number_of_entries = sub_drop_down_header_entries[header_name][menu_item_name]
		drop_down_item_height = 19
		drop_down_Y_boundaries = [[sub_drop_down_starting_point, sub_drop_down_starting_point + drop_down_item_height]]
		drop_down_counter = 1
		while(drop_down_counter < number_of_entries):
			previous_drop_down_height = drop_down_Y_boundaries[drop_down_counter - 1][1]
			drop_down_Y_boundaries.append([previous_drop_down_height, previous_drop_down_height + drop_down_item_height])
			drop_down_counter += 1
		return drop_down_Y_boundaries
	'''
	Function: header_drop_down_values
	Input: 
		- header_name: This is the name of the header that is in focus, aka the header that was clicked.
		- entry_number: This is the index number down the menu drop down that the item lies. Counting starts at zero.
	Functionality: 
		- This is a dictionary I hand typed, each header drop down item is typed so that it can be logged immediately when
		  clicked.
	'''
	def header_drop_down_values(self, header_name, entry_number):
		drop_down_values = {
			"File": ["Open", "Close ProgramName", "CloseOthers", "CloseAll", "SaveAll", "Save ProgramName As",
					 "Save ProgramName", "ImportFile", "BatchImport", "OpenFileSystem", "AddToProgram", "ExportProgram",
					 "LoadPDBFile", "ParseCSource", "Print", "PageSetup", "Configure",
					 "SaveTool", "SaveToolAs", "Export", "CloseTool", "ExitGhidra"],
			"Edit": ["ToolOptions", "OptionsFor ProgramName", "DWARFExternalDebugConfig", "SymbolServerConfig", "ClearCodeBytes", "ClearWithOptions", "ClearFlowAndRepair",
					 "Undo", "Redo"],
			"Analysis": ["AutoAnalyze ProgramName", "AnalyzeAllOpen", "OneShot", "AnalyzeStack"],
			"Graph": ["BlockFlow", "CodeFlow", "Calls", "CallsUsingModel", "Data", "AppendGraph", "ReuseGraph", "ShowLocation", "GraphOutput"],
			"Navigation": ["ClearHistory", "NextHistoryFunction", "PreviousHistoryFunction", "GoTo", "GoToSymbolSource",
						   "GoToNextFunction", "GoToPreviousFunction", "GoToProgram", "GoToLastActiveProgram",
						   "GoToLastActiveComponent", "NextSelectedRange", "PreviousSelectedRange", "NextHighlightRange",
						   "PreviousHighlightRange", "NextColorRange", "PreviousColorRange"],
			"Search": ["LabelHistory", "ProgramText", "RepeatTextSearch", "Memory", "RepeatMemorySearch", "ForMatchingInstructions",
					   "ForAddressTables", "ForDirectReferences", "ForInstructionPatterns", "ForScalars", "ForStrings"],
			"Select": ["ProgramChanges", "AllFlowsFrom", "AllFlowsTo", "LimitedFlowsFrom", "LimitedFlowsTo", "Subroutine",
					   "DeadSubroutines", "Function", "FromHighlight", "ProgramHighlight", "ScopedFlow", "AllInView",
					   "ClearSelection", "Complement", "Bytes", "Data", "Instructions", "Undefined", "CreateTableFromSelection",
					   "RestoreSelection", "BackRefs", "ForwardRefs"],
			"Tools": ["ProcessorManual", "ProgramDifferences", "GenerateChecksum"],
			"Window": ["Bookmarks", "BundleManager", "Bytes COLON ProgramName", "ChecksumGenerator", "Comments", "Console", "DataTypeManager", 
					   "DataTypePreview", "Decompiler", "DefinedData", "DefinedStrings", "DisassembledView", "EquatesTable",
					   "ExternalPrograms", "FunctionCallGraph", "FunctionCallTrees", "FunctionGraph", "FunctionTags", 
					   "Functions", "Listing COLON ProgramName", "MemoryMap", "ProgramTrees", "Python", "RegisterManager", "RelocationTable",
					   "ScriptManager", "SymbolReferences", "SymbolTable", "SymbolTree"],
			"Help": ["Contents", "GhidraAPIHelp", "UserAgreement", "InstalledProcessors", "AboutGhidra", "About ProgramName"]
		}
		return drop_down_values[header_name][entry_number]

	def return_sub_drop_down_values(self):
		sub_drop_down_values = {
			"File": {
							"Export":["ExportTool", "ExportDefaultTool"]
					},
			"Edit": {},
			"Analysis": {
							"OneShot": ["ASCIIStrings", "AggresiveInstructionFinder", "CallConventionID", "CallFixupInstaller",
											"CreateAddressTables", "DecompilerParameterID", "DecompilerSwitchAnalysis",
											"DemanglerGNU", "EmbeddedMedia", "FunctionID", "FunctionStartSearch", "NonReturningFunctionsDiscovered",
											"SharedReturnCalls", "Stack", "VariadicFunctionSignatureOverride"]
						},
			"Graph": {
							"CallsUsingModel": ["IsolatedEntry", "MultipleEntry", "OverlappedCode", "PartitionedCode"],
							"Data": ["FromReferences", "ToReferences", "To/FromReferences"],
							"GraphOutput": ["DefaultGraphDisplay", "GraphExport"]
					 },
			"Navigation": {},
			"Search": {
							"ForMatchingInstructions": ["ExcludeOperands", "IncludeOperands", "IncludeOperandsExceptConstants"]
					  },
			"Select":  {
							"ProgramHighlight": ["EntireSelection", "Clear", "AddSelection", "SubtractSelection"],
							"ScopedFlow": ["ForwardScopedFlow", "ReverseScopedFlow"]
					   },
			"Tools": {},
			"Window": {}, #This is the only intentional non-instrumentation, we have a sub menu because of the plugin, normal ghidra doesn't have one.
			"Help": {}
		}
		return sub_drop_down_values
	'''
	Function: header_sub_drop_down_values
	Input: 
		- header_name: This is the name of the header that is in focus, aka the header that was clicked.
		- menu_name: The drop down item name that has a sub-menu.
		- entry_number: This is the index number down the sub-menu drop down that the item lies. Counting starts at zero.
	Functionality: 
		- This is a dictionary I hand typed, each header drop down item is typed so that it can be logged immediately when
		  clicked.
	'''
	def header_sub_drop_down_values(self, header_name, menu_name, entry_number):
		sub_drop_down_values = self.return_sub_drop_down_values()
		return sub_drop_down_values[header_name][menu_name][entry_number]
	'''
	These are various getters / setters used in the program. 
		- the widths are hard coded for the menu drop downs.
		- Only setters for for the focused header and the menu drop down name with a sub menu.
	'''
	def get_header_locations(self):
		return self.header_locations
	def get_header_focus(self):
		return self.header_focused
	def get_header_drop_down_right_pixel(self):
		return self.header_drop_down_right_X
	def get_header_drop_down_locations(self, header_name):
		return self.header_drop_down_locations[header_name]
	def get_drop_down_name(self):
		return self.drop_down_name
	def get_sub_drop_downs(self):
		return self.sub_drop_downs
	def get_header_sub_drop_down_locations(self):
		return self.header_sub_drop_down_locations
	def get_ghidra_window_coordinates(self):
		return self.all_ghidra_window_coords
	def get_function_graph_block_coordinates(self):
		return self.function_graph_block_coords
	def get_current_ghidra_window(self):
		return self.current_ghidra_window
	def get_current_ghidra_header(self):
		return self.current_ghidra_header
	def get_current_ghidra_drop_down(self):
		return self.current_ghidra_drop_down
	def get_current_ghidra_sub_menu(self):
		return self.current_ghidra_sub_menu
	def get_window_entry_time(self):
		return self.time_in_ghidra_window
	def get_header_entry_time(self):
		return self.header_entry_time
	def get_header_drop_down_entry_time(self):
		return self.time_in_header_drop_down
	def get_header_sub_menu_entry_time(self):
		return self.time_in_header_sub_menu
	def get_focused_window(self):
		return self.focused_window
	def get_header_menu_widths(self):
		header_menu_widths = {
			"File": 219,
			"Edit": 285,
			"Analysis": 203,
			"Graph": 183,
			"Navigation": 357,
			"Search": 293,
			"Select": 323,
			"Tools": 199,
			"Window": 363,
			"Help": 153,
		}
		return header_menu_widths
	def get_header_sub_menu_widths(self):
		sub_drop_down_values = {
			"File": {"Export": 156},
			"Edit": {},
			"Analysis": {"OneShot": 259},
			"Graph": {"CallsUsingModel": 132, "Data": 150, "GraphOutput": 174},
			"Navigation": {},
			"Search": {"ForMatchingInstructions": 251 },
			"Select":  {"ProgramHighlight": 205, "ScopedFlow": 156},
			"Tools": {},
			"Window": {}, #This is the only intentional non-instrumentation, we have a sub menu because of the plugin, normal ghidra doesn't have one.
			"Help": {}
		}
		return sub_drop_down_values	
	def set_header_focus(self, header_name):
		self.header_focused = header_name
	def set_drop_down_name(self, new_drop_down_name):
		self.drop_down_name = new_drop_down_name
	def set_ghidra_window_coordinates(self, new_ghidra_coordinates):
		self.all_ghidra_window_coords = new_ghidra_coordinates
	def set_function_graph_block_coordinates(self, new_function_graph_block_coords):
		self.function_graph_block_coords = new_function_graph_block_coords
	def set_current_ghidra_window(self, new_window):
		self.current_ghidra_window = new_window
	def set_current_ghidra_header(self, new_ghidra_header):
		self.current_ghidra_header = new_ghidra_header
	def set_current_ghidra_drop_down(self, new_header_drop_down):
		self.current_ghidra_drop_down = new_header_drop_down
	def set_current_ghidra_sub_menu(self, new_ghidra_sub_menu):
		self.current_ghidra_sub_menu = new_ghidra_sub_menu	
	def set_window_entry_time(self, new_entry_time):
		self.time_in_ghidra_window = new_entry_time
	def set_header_entry_time(self, new_entry_time):
		self.header_entry_time = new_entry_time	
	def set_header_drop_down_entry_time(self, new_entry_time):
		self.time_in_header_drop_down = new_entry_time	
	def set_header_sub_menu_entry_time(self, new_entry_time):
		self.time_in_header_sub_menu = new_entry_time	
	def set_focused_window(self, new_focus):
		self.focused_window = new_focus

'''
class: monitor_ghidra_borders
Functionality:
	- When the program starts ghidra may not be up yet, as it is used windows may be hidden, re-sized, etc. To combat the
	  fluid environment in ghidra we regularly check to make sure that everything is still visible and in the same location.

	- In the event we have not found an item yet, or we have found one and then failed to find it in a check up, we will search
	  for that items every 10 seconds. This can happen if the user is filling out a survey and the screen is blocked for example.
	
	- This is run in a thread, so it all happens asynchronously with out interrupting the mouse monitor code.

@author Jeremy Johnson
'''
class monitor_ghidra_borders:
	base_path = os.path.dirname(os.path.abspath(__file__))
	path_to_images = base_path + "/images/"	
	#Every 10 seconds we refresh the coordinates of all items in the ghidra windows.
	ghidra_refresh_interval = 10
	def __init__(self, ghidra_windows, given_event_queue):
		self.event_queue = given_event_queue
		self.ghidra_windows = ghidra_windows
		self.last_search_time = time.time()
		self.running = True

		with mss.mss() as sct:
			#sct.monitors[0] will show information on the whole monitor setup.
			screen_pixel_count = sct.monitors[0]["width"] + sct.monitors[0]["height"]
			if(screen_pixel_count > 4900):
				#Some crazy monitor set ups can have a ton of pixels total. 10 seconds should be enough for 2 3440x1440p screens, enough for 1 4k + 1 1080p.
				self.ghidra_refresh_interval = 10
			elif(screen_pixel_count < 4900 and screen_pixel_count > 3100):
				#Single 3440x1440p monitor has 4880 pixels. Takes ~2-3 seconds per search. 
				self.ghidra_refresh_interval = 5
			else:
				#A standard 1920x1080p monitor has 3000 pixels. Takes < 2 seconds to search
				self.ghidra_refresh_interval = 3

	def create_paths_to_images(self):
		#Each generic window in ghidra we want coordinates for requires three data points: The unique top left image, 
		#	the "X" coordinates (already handled), and the bottom right/left image.
		#NOTE: For all of these, order matters. Always put the not selected / gray one first. all but one will be not selected, so checking for them first is faster.
		all_paths = {}
		listing_view_paths = [[self.path_to_images + "ghidra_image.png"], [self.path_to_images + "task_survey_bot_right.png"]]
		all_paths["TaskSurvey"] = listing_view_paths
		listing_view_paths = [[self.path_to_images + "defined_strings_not_selected.png", self.path_to_images + "defined_strings_selected.png"], [self.path_to_images + "defined_strings_bot_right.png"]]
		all_paths["DefinedStrings"] = listing_view_paths
		symbol_tree_paths = [[self.path_to_images + "symbol_tree_gray.png", self.path_to_images + "symbol_tree_selected.png"], [self.path_to_images + "filter_icon.png"]]
		all_paths["SymbolTree"] = symbol_tree_paths
		symbol_tree_paths = [[self.path_to_images + "data_type_manager_not_selected.png", self.path_to_images + "data_type_manager_selected.png"], [self.path_to_images + "filter_icon.png"]]
		all_paths["DataTypeManager"] = symbol_tree_paths
		symbol_tree_paths = [[self.path_to_images + "decompiler_not_selected.png", self.path_to_images + "decompiler_selected.png"], [self.path_to_images + "decompiler_bot_right.png", self.path_to_images + "tabs_bot_right.png"]]
		all_paths["Decompiler"] = symbol_tree_paths
		listing_view_paths = [[self.path_to_images + "program_trees_not_selected.png", self.path_to_images + "program_trees_selected.png"], [self.path_to_images + "program_trees_bot_right.png"]]
		all_paths["ProgramTrees"] = listing_view_paths
		listing_view_paths = [[self.path_to_images + "function_graph_gray.png", self.path_to_images + "function_graph_selected.png"], [self.path_to_images + "function_graph_bot_right_wifi_image.png", self.path_to_images + "function_graph_bot_right.png", self.path_to_images + "tabs_bot_right.png"]]
		all_paths["FunctionGraph"] = listing_view_paths
		listing_view_paths = [[self.path_to_images + "listing_gray.png", self.path_to_images + "listing_selected.png"], [self.path_to_images + "down_arrow.png"]]
		all_paths["DisplayListing"] = listing_view_paths
		symbol_tree_paths = [[self.path_to_images + "task_instructions_not_selected.png", self.path_to_images + "task_instructions_selected.png"], [self.path_to_images + "task_instructions_bot_right.png", self.path_to_images + "task_instructions_bot_right_selected.png"]]
		all_paths["TaskInstructions"] = symbol_tree_paths
		return all_paths

	def ghidra_reposition_check(self):
		#Immediately get the time, this is the time the screen shot is taken. Finding everything takes a few seconds, but the items positions are in this 
		#location in this precise moment in time!
		curr_time = time.time()
		#Finding the coordinates of the main windows in ghidra can all use *most* of the same code.
		#The "header" code is super unique and requires its own function.
		#First, get the screenshot bytes
		monitor_bytes = self.ghidra_windows.get_screen_shot_bytes()
		#Then I get all X marks on the ghidra window. These are needed for finding the coordinates of the windows.
		all_X_coords = self.ghidra_windows.find_all_X_marks(monitor_bytes)
		
		#all_paths is a dictionary, key: window name, value: 2-d list with two entries. First: unique top left images. Second: bottom right/left images
		all_paths = self.create_paths_to_images()
		pool_input_argument = []
		for window_name in all_paths:
			#The pool function expects arguments to look like this. They need to be in the same variable.
			pool_input_argument.append({"monitor bytes": monitor_bytes, "X coordinates": all_X_coords, "window name": window_name, "paths": all_paths[window_name]})

		pool = Pool()
		all_coordinates = pool.map(self.ghidra_windows.find_ghidra_view_coordinates, pool_input_argument)
		pool.close()
		pool.join()
		#this returns a list with one entry per window as a dictionary. I want a single dictionary. Translate here.
		ghidra_coordinates = {}
		for dictionary in all_coordinates:
			window_name = list(dictionary.keys())[0]
			ghidra_coordinates[window_name] = dictionary[window_name]

		#Now, before finishing up I want to run through all entries and check for overlaps. If specific items are hidden the coordinates will not report correctly.
		#	- This is extremely unlikely, however I would rather check and be 100% sure of all coordinates given.
		for window_name in ghidra_coordinates:
			#Note: This loop goes over all items in both ways. It looks for one to be a subset of the other, so we need to check both ways. 
			top_left_coords = ghidra_coordinates[window_name][0]
			bot_right_coords = ghidra_coordinates[window_name][1]
			for inner_window_name in ghidra_coordinates:
				if(window_name == inner_window_name):
					continue
				inner_top_left_coords = ghidra_coordinates[inner_window_name][0]
				inner_bot_right_coords = ghidra_coordinates[inner_window_name][1]
				if(top_left_coords[0] == -1 or inner_top_left_coords[0] == -1):
					continue
				#If I draw a square, the "inner" square corners can't be inside any other coordinates. These check right side
				if(top_left_coords[0] <= inner_bot_right_coords[0] and bot_right_coords[0] >= inner_bot_right_coords[0]):
					if(top_left_coords[1] <= inner_top_left_coords[1] and bot_right_coords[1] >= inner_top_left_coords[1]):
						#This is the top right of the window name
						ghidra_coordinates[window_name] = [[-1, -1], [-1, -1]]
					elif(top_left_coords[1] <= inner_bot_right_coords[1] and bot_right_coords[1] >= inner_bot_right_coords[1]):
						#This is the bottom right of the window name.
						ghidra_coordinates[window_name] = [[-1, -1], [-1, -1]]
				#These check the left side, top and bottom.
				if(top_left_coords[0] <= inner_top_left_coords[0] and bot_right_coords[0] >= inner_top_left_coords[0]):
					if(top_left_coords[1] <= inner_top_left_coords[1] and bot_right_coords[1] >= inner_top_left_coords[1]):
						#This is the top left corner of "window_name" being inside "inner_window_name" window.
						ghidra_coordinates[window_name] = [[-1, -1], [-1, -1]]
					elif(top_left_coords[1] <= inner_bot_right_coords[1] and bot_right_coords[1] >= inner_bot_right_coords[1]):
						'''
						This is the bottom left corner of "window_name" being inside "inner_window_name" window.
						There are a few very nuanced edge cases with the bottom left. We have to check the top right "X" locations separately for this instance.
						Since both "X" images are required to be found, I know that the window in front of the other MUST be the one below and to the left. If
						"window_name" is below and to the left, then it is in fact in the fore ground and the other one must be removed!
						'''
						if(top_left_coords[1] >= inner_top_left_coords[1] and bot_right_coords[0] <= inner_bot_right_coords[0]):
							ghidra_coordinates[inner_window_name] = [[-1, -1], [-1, -1]]
						else:
							ghidra_coordinates[window_name] = [[-1, -1], [-1, -1]]

		#Check the windows to see if our current focus window is still known. If it isn't, we need to remove focus from that window.
		focused_window = self.ghidra_windows.get_focused_window()
		if(focused_window != ""):
			for window_name in ghidra_coordinates:
				if(window_name == focused_window and ghidra_coordinates[window_name][0][0] == -1):
					self.ghidra_windows.set_focused_window("")

		#The header positions are a separate function call with super specific code. 
		self.ghidra_windows.find_all_header_positions()
		#Before we record these window coordinates, I want to manually determine the locations of the back and forward buttons.
		#To do this I will use the header locations and compute the boundaries from there.
		header_coords = self.ghidra_windows.get_header_locations()
		if(header_coords != {}):
			upper_boundary = int(header_coords["upper coord"] + 3)
			lower_boundary = int(header_coords["upper coord"] + 24)
			back_button_left_boundary = int(header_coords["File"][1] + 5)
			back_button_right_boundary = int(header_coords["File"][1] + 40)
			forward_button_left_boundary = int(header_coords["File"][1] + 41)
			forward_button_right_boundary = int(header_coords["File"][1] + 76)
			ghidra_coordinates["BackButton"] = [[back_button_left_boundary, upper_boundary], [back_button_right_boundary, lower_boundary]]
			ghidra_coordinates["ForwardButton"] = [[forward_button_left_boundary, upper_boundary], [forward_button_right_boundary, lower_boundary]]
		else:
			#If we never found the locations of the headers then just leave these as -1.
			ghidra_coordinates["BackButton"] = [[-1,-1],[-1,-1]]
			ghidra_coordinates["ForwardButton"] = [[-1,-1], [-1,-1]]		

		self.ghidra_windows.set_ghidra_window_coordinates(ghidra_coordinates)
		#Use the original screenshot bytes to find the time in the ghidra GUI.
		ocr_time_stamp = -1
		#Ensure that we are using "TaskInstructions" and that the coordinates were found
		if("TaskInstructions" in ghidra_coordinates and ghidra_coordinates["TaskInstructions"][0][0] != -1):
			top_left_X = ghidra_coordinates["TaskInstructions"][0][0]
			top_left_Y = ghidra_coordinates["TaskInstructions"][0][1]
			top_right_X, top_right_Y = self.ghidra_windows.find_corresponding_X_coordinate(top_left_X, top_left_Y, all_X_coords)
			ocr_time_stamp = self.ghidra_windows.find_time_stamp(monitor_bytes, top_right_X, top_right_Y)

		#Before we finish, update queue with the new-found positions. This logs them.
		log_entry = {"CoordinateEvent":{"Timestamp": curr_time, "InstrumentationType": "External",
										"GhidraTime": ocr_time_stamp, "Coordinates": ghidra_coordinates}}
		json_str = json.dumps(log_entry)
		self.event_queue.put(json_str, True, 5)
		#print(log_entry)

	#No arguments, just loops indefinitely calling ghidra_reposition_check() on a set interval.
	def monitor_ghidra_locations(self):
		#Right when we start, try to find the coordinates of everything.
		s = time.time()
		self.ghidra_reposition_check()
		e = time.time()
		while(self.running):
			#On a regular interval we check for all windows to still be visible / in the same position.
			if(self.last_search_time + self.ghidra_refresh_interval < time.time()):
				self.last_search_time = time.time()
				s = time.time()
				self.ghidra_reposition_check()
				e = time.time()
				#print("Search Time: " + str(round(e-s,3)))			
			time.sleep(1)

	def stop(self):
		self.running = False


'''
class: monitor_graph_blocks
Functionality:
	- Ghidra's function graph renders blocks which contain assembly instructions. The goal of this class is to regularly identify
	  coordinates within the function graph window. On average this takes significantly less than 2 seconds to run because the 
	  openCV libraries are examining a cropped set of pixels that only include the function graph plugin. Reducing the pixels 
	  directly helps the runtime.

	- If the function graph coordinates are not found in the class "monitor_ghidra_borders", then this code will not run as we don't
	  know what region to examine.

@author Jeremy Johnson
'''
class monitor_graph_blocks:
	base_path = os.path.dirname(os.path.abspath(__file__))
	path_to_images = base_path + "/images/"	
	#Every 2 seconds we check the coordinates within the function graph, interval set here.
	graph_refresh_interval = 2
	def __init__(self, ghidra_windows, given_event_queue):
		self.event_queue = given_event_queue
		self.ghidra_windows = ghidra_windows
		self.last_search_time = time.time()
		self.running = True

	def find_block_name(self, monitor_bytes, top_left_coords):
		top_left_x = top_left_coords[0]
		top_left_y = top_left_coords[1]
		#cv_monitor_bytes = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_RGB2BGR)
		cv_monitor_bytes = cv.cvtColor(np.array(monitor_bytes), cv.COLOR_BGR2GRAY)
		(thresh, black_and_white_bytes) = cv.threshold(cv_monitor_bytes, 127, 255, cv.THRESH_BINARY)

		#These offsets are specific to the image I took to create a close fit, but not *too* close otherwise we lose accuracy.
		y_coords = [top_left_y + 1, top_left_y + 17]
		x_coords = [top_left_x + 8, top_left_x + 75]
		cropped_image = black_and_white_bytes[y_coords[0]: y_coords[1], x_coords[0]:x_coords[1]]

		api = tesserocr.PyTessBaseAPI()
		api.SetVariable('tessedit_char_whitelist', "abcdef1234567890")
		api.SetImage(Image.fromarray(cropped_image))
		ocr_block_name = api.GetUTF8Text()
		if("\n" in ocr_block_name):
			ocr_block_name = ocr_block_name.replace("\n","")
		#In the event the names are not coming up correct, please try to utilize this code to write the cropped image to a png file for examination.
		#if(len(ocr_block_name) < 7):
		# These are a few different ways I was writing the files to disk for verification. Keeping for prosperity.
		#	cv_monitor_bytes = cv.cvtColor(np.array(cropped_image), cv.COLOR_RGB2BGR)
		#	cv.imwrite("test.png", cv_monitor_bytes)	
		#	cv_monitor_bytes = cv.cvtColor(np.array(cropped_image), cv.COLOR_BGR2GRAY)
		#	(thresh, blackAndWhiteImage) = cv.threshold(cropped_image, 127, 255, cv.THRESH_BINARY)
		#	cv.imwrite("test.png", blackAndWhiteImage)
		return ocr_block_name

	# This creates a dictionary with paths to screen shots already taken. These are used to find all images in the function graph.
	def create_paths_to_images(self):
		all_paths = {}
		top_right_paths = [self.path_to_images + "graph_block_top_right.png"]
		all_paths["TopRight"] = top_right_paths
		bot_left_paths = [self.path_to_images + "graph_block_bot_left.png"]
		all_paths["BotLeft"] = bot_left_paths		
		return all_paths

	#This takes a screen grab and saves the bytes in memory.
	def get_cropped_function_graph_bytes(self, function_graph_coords):
		top_y = function_graph_coords[0][1] + 19
		bottom_y = function_graph_coords[1][1]
		left_x = function_graph_coords[0][0]
		right_x = function_graph_coords[1][0]
		function_graph_width = right_x - left_x
		function_graph_height = bottom_y - top_y
		with mss.mss() as sct:
			#sct.monitors will show information on the whole monitor setup.
			#PARAM: scr.monitors[0] -> {'left': 0, 'top': 0, 'width': 5360, 'height': 3317}
			monitor_boundaries = {"left": left_x, "top": top_y, "width": function_graph_width, "height": function_graph_height}
			sct_img = sct.grab(monitor_boundaries) #[0] gives me the whole screen realestate. [1] gives first screen, etc.
			img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
			return img, left_x, top_y
		return -1,-1,-1

	def generate_block_coordinate_event(self, graph_blocks, curr_time, ocr_time_stamp):
		log_entry = {"BlockCoordinateEvent":{"Timestamp": curr_time, "InstrumentationType": "External",
											 "GhidraTime": ocr_time_stamp, "Coordinates": graph_blocks}}
		json_str = json.dumps(log_entry)
		self.event_queue.put(json_str, True, 5)

	#Known issue: If the function graph is tabbed with another window it will fail to find the correct bottom right corner.
	def find_graph_block_coordinates(self):
		#Immediately get the time, this is the time the screen shot is taken. Finding everything takes a few seconds, but the items positions are in this 
		#location in this precise moment in time!
		curr_time = time.time()
		#Grab the monitor bytes right away so the OCR time gotten at the very end is from the correct time.
		monitor_bytes = self.ghidra_windows.get_screen_shot_bytes()
		#Output of coordinates, empty if we fail to find them.
		graph_blocks = {}
		#Use the original screenshot bytes to find the time in the ghidra GUI.
		ocr_time_stamp = -1
		all_coordinates = self.ghidra_windows.get_ghidra_window_coordinates()
		#Ensure that we are using "TaskInstructions" and that the coordinates were found
		if("TaskInstructions" in all_coordinates and all_coordinates["TaskInstructions"][0][0] != -1):
			top_left_X = all_coordinates["TaskInstructions"][0][0]
			top_left_Y = all_coordinates["TaskInstructions"][0][1]
			all_X_coords = self.ghidra_windows.find_all_X_marks(monitor_bytes)
			top_right_X, top_right_Y = self.ghidra_windows.find_corresponding_X_coordinate(top_left_X, top_left_Y, all_X_coords)
			ocr_time_stamp = self.ghidra_windows.find_time_stamp(monitor_bytes, top_right_X, top_right_Y)

		#No known coordinates for the function graph, nothing to do here.
		if(len(all_coordinates) == 0 or all_coordinates["FunctionGraph"][0][0] == -1):
			self.ghidra_windows.set_function_graph_block_coordinates(graph_blocks)
			self.generate_block_coordinate_event(graph_blocks, curr_time, ocr_time_stamp)
			return
		function_graph_coords = all_coordinates["FunctionGraph"]
		#First, get the screenshot bytes cropped around the function graph. the "x_offset" and "y_offset" will be used to restore coordinates to the global value
		cropped_monitor_bytes, x_offset, y_offset = self.get_cropped_function_graph_bytes(function_graph_coords)
		# Code for checking monitor bytes, this writes the image to a file.
		#cv_monitor_bytes = cv.cvtColor(np.array(cropped_monitor_bytes), cv.COLOR_RGB2BGR)
		#cv.imwrite("test.png", cv_monitor_bytes)		
		image_paths = self.create_paths_to_images()
		#It is possible that they are not zoomed into the function graph. If we fail to find the top right, completely abort.
		all_top_right_coords, image_counter = self.ghidra_windows.find_all_sub_images(image_paths["TopRight"], cropped_monitor_bytes, 0)
		if(all_top_right_coords == -1 or len(all_top_right_coords["coordinates"]) == 0):
			self.ghidra_windows.set_function_graph_block_coordinates(graph_blocks)
			self.generate_block_coordinate_event(graph_blocks, curr_time, ocr_time_stamp)
			return
		top_right_image_width = all_top_right_coords["width"] + 4
		all_bot_left_coords, image_counter = self.ghidra_windows.find_all_sub_images(image_paths["BotLeft"], cropped_monitor_bytes, 0)
		if(all_bot_left_coords == -1 or len(all_bot_left_coords["coordinates"]) == 0):
			self.ghidra_windows.set_function_graph_block_coordinates(graph_blocks)
			self.generate_block_coordinate_event(graph_blocks, curr_time, ocr_time_stamp)			
			return
		'''
		The problem:
		When creating these images I realized that the boxes are not always rendered the same. The "boldness" of the lines on the bottom varies,
		and the top left box occasionally has an extra line of pixels. The top right is not a problem, the image is consistent.

		The solution:
		The three dots on the left of each line are consistent, although not unique. The code finds all of them, then loops through them all and
		identifies the bottom one for each block. From that final coordinate, I know I can go down and to the left by a small amount of pixels and
		arrive at the bottom left corner.
		
		The algorithm:
		Each set of three dots is 16 pixels below the next. If the boxes are aligned on the same x-axis, then the output will not be continuous for
		each box. In the example below, you can see [11,337] is in the middle of a chain of other coordinates. 

		[[208, 298], [208, 314], [208, 330], [11, 337], [208, 346], [208, 362]]

		I know that the first coordinates will be the top most coordinate in a series, I just don't know if the ones that follow are a part of the 
		same chain. I know the y-coordinates will be the same, and the x-xoordinates will be 16 pixels below the previous. So I can loop through
		all coordinates and the last coordinate that meets these criteria will be my bottom left coordinate!
		'''
		final_bot_left_coords = []
		bot_left_coords = all_bot_left_coords["coordinates"]
		while(len(bot_left_coords) > 0):
			unused_coordinates = []
			x_coord = bot_left_coords[0][0]
			prev_y_coord = bot_left_coords[0][1]
			counter = 1
			while(counter < len(bot_left_coords)):
				coordinates = bot_left_coords[counter]
				if(coordinates[0] == x_coord and coordinates[1] == prev_y_coord+16):
					prev_y_coord = coordinates[1]
				else:
					unused_coordinates.append(coordinates)
				counter += 1

			#Adjust the coordinates by 1 on the X and 17 on the Y.
			final_x_coord = x_coord - 1
			final_y_coord = prev_y_coord + 17
			final_bot_left_coords.append([final_x_coord, final_y_coord])
			bot_left_coords = unused_coordinates

		#Now I have the bottom left of these blocks. I need to associate them with the top right so I can create boxes.
		top_right_coords = all_top_right_coords["coordinates"]
		name_skeleton = "untitled_"
		counter = 0
		while(counter < len(top_right_coords)):
			top_right_coord = top_right_coords[counter]
			best_bot_left_coordinate = -1
			for bot_left_coord in final_bot_left_coords:
				#First two checks verify that the bot left is down and to the left of the top right coordinate
				#The final check ensures that no more than 500 pixels separates bottom left X from top right X. This prevents a second box from being incorrectly used.
				if(bot_left_coord[0] < top_right_coord[0] and bot_left_coord[1] > top_right_coord[1] and top_right_coord[0] - 500 < bot_left_coord[0]):
					if(best_bot_left_coordinate == -1):
						best_bot_left_coordinate = bot_left_coord
					else:
						if(best_bot_left_coordinate[0] < bot_left_coord[0] and best_bot_left_coordinate[1] > bot_left_coord[1]):
							best_bot_left_coordinate = bot_left_coord

				#Two cases, either best_bot_left_coordinate has been set or it hasn't.
			if(best_bot_left_coordinate != -1):
				block_name = name_skeleton + str(counter)
				#The top right coordinate given is the "top left" of the image. This moves it to the top right of the image, aka the top right of the function block.
				top_right_coord[0] += top_right_image_width
				top_right_coord[1] -= 2
				graph_blocks[block_name] = [best_bot_left_coordinate,top_right_coord]
			counter += 1

		#These coordinates are not necessarily correct. It is possible that a top right happens and the bottom left is used twice. 
		#When this happens, the top right coordinate that is the closest (y coordinate lowest..?) is the one to take.
		all_keys = list(graph_blocks.keys())
		counter = 0
		while(counter < len(all_keys)):
			#Note: I need the key disjoint from the loop so that I can delete the key in the loop. If I did a for loop iterator it would break when I delete the key.
			key = all_keys[counter]
			if(key not in graph_blocks):
				counter += 1
				continue
			coordinate_to_verify = graph_blocks[key]
			inner_counter = counter + 1
			while(inner_counter < len(all_keys)):
				inner_key = all_keys[inner_counter]
				if(inner_key not in graph_blocks):
					inner_counter += 1
					continue
				second_coordinates = graph_blocks[inner_key]
				#Bottom left being the same means there is a problem!
				if(coordinate_to_verify[0][0] == second_coordinates[0][0] and coordinate_to_verify[0][1] == second_coordinates[0][1]):
					#One of these two needs to be YEETED!
					if(coordinate_to_verify[1][1] < second_coordinates[1][1]):
						#If we delete the key on the outer loop we do NOT want to continue, as this might cause a double delete. The break solves this.
						del graph_blocks[key]
						break
					else:
						del graph_blocks[inner_key]
				inner_counter += 1
			counter += 1

		#Translate coordinates to be top left and bot right so it is consistent with the coordinate events.
		for key in graph_blocks:
			coordinates = graph_blocks[key]
			top_left = [coordinates[0][0], coordinates[1][1]]
			bot_right = [coordinates[1][0], coordinates[0][1]]
			graph_blocks[key] = [top_left, bot_right]


		#Find the name of each block. I can use the top left coordinates and make a box around the name in the "find_block_name" function.
		all_keys = list(graph_blocks.keys())
		counter = 0
		while(counter < len(all_keys)):
			key = all_keys[counter]
			top_left_x = graph_blocks[key][0]
			name = self.find_block_name(cropped_monitor_bytes, top_left_x)
			tmp_coords = graph_blocks[key]
			del graph_blocks[key]
			graph_blocks[name] = tmp_coords
			counter += 1

		#Lastly, let's change the coordinates back to the "un-cropped" values, values pertaining to the screen as a whole.
		for key in graph_blocks:
			coords = graph_blocks[key]
			#These are numpy 64 bit types, JSON requires non numpy types. I cast them all to ints in the final conversion.
			graph_blocks[key] = [[int(coords[0][0]+x_offset), int(coords[0][1]+y_offset)], [int(coords[1][0]+x_offset), int(coords[1][1]+y_offset)]]
		self.ghidra_windows.set_function_graph_block_coordinates(graph_blocks)
		self.generate_block_coordinate_event(graph_blocks, curr_time, ocr_time_stamp)

	#No arguments, just loops indefinitely calling ghidra_reposition_check() on a set interval.
	def monitor_ghidra_graph_blocks(self):
		#Right when we start, try to find the coordinates of everything.
		self.find_graph_block_coordinates()
		while(self.running):
			#On a regular interval we check for all windows to still be visible / in the same position.
			if(self.last_search_time + self.graph_refresh_interval < time.time()):
				self.last_search_time = time.time()
				s = time.time()
				self.find_graph_block_coordinates()
				e = time.time()
				#print("Function Block Search Time: " + str(round(e-s,3)))			
			time.sleep(1)

	def stop(self):
		self.running = False

