from ghidra_components import *
from ghidra_logger import *
import threading

log_file_name = "GhidraClickLogs.log"
global RELEASE
#To run locally, set this to False. To run on Vagrant VM, set it to True and execute "vagrant up --provision"
if(os.path.isdir("/vagrant")):
	#This means we are running on vagrant, so log paths go to official log folder
	RELEASE = True
	log_path = "/opt/cava-log/" + log_file_name
else:
	#Running locally, log file goes in directory with this file.
	RELEASE = False
	log_path = os.path.dirname(os.path.abspath(__file__)) + "/" + log_file_name

global ghidra_locations
global event_queue

#This is needed for the testing phase to set the global variables in this file.
def set_global_vars(ghidra_locs, event_q, rel):
	global RELEASE, ghidra_locations, event_queue
	ghidra_locations = ghidra_locs
	event_queue = event_q
	RELEASE = rel

'''
Parameters:
	x - The X coordinate of the button press
	y - The Y coordinate of the button press
	button - The mouse button that was pressed, namely "left", "right", or "middle" (clicking scroll wheel)
	pressed - "False" when the click is released, "True" when the click is pressed.
Functionality:
	For the headers, we have pre-computed the exact locations of the header locations. So when the user clicks
	on a header I can immediately know if this brings up a menu. When the menu appears, the menu is referred to
	in the code as "focused". A focused header tells the code that there is a menu present, the coordinates for
	this menu are pre-computed and all boundaries are already known.

	When a follow up click happens, it will use the clicks coordinates to determine if it was in the menu drop down.

	If a sub-menu is active (from on_move() monitoring) then the sub-menu coordinates will also be checked for a click.

	"set_focus" is a variable used to decide if focus was set on a header or not. I use this variable for edge cases as well
	where a click caused no change in the menu drop down.

	We also monitor for clicks in ghidra windows that have been pre calculated. Currently no action is taken besides
	logging in it.
Return Value:
	N/A

@author Jeremy Johnson
'''
def on_click(x,y,button,pressed):
	global ghidra_locations, event_queue, RELEASE
	#Immediately get the time so that it is as accurate as possible.
	click_time = time.time()
	focused_window = ghidra_locations.get_focused_window()
	if(button.name == "left"):
		button_click_type = "LeftClick"
	elif(button.name == "right"):
		button_click_type = "RightClick"
	elif(button.name == "middle"):
		button_click_type = "MiddleClick"
	else:
		button_click_type = button.name #Could be a strange mapping on a special mouse. 

	#First check to see if the user clicked the headers, for now print it out.
	#Ghidra is big dumb dumb and lets left / right / middle clicks register on headers. WHY!!!!
	if((button.name != "left" and button.name != "right" and button.name != "middle") or pressed == True):
		return
	#if((button.name == "left" or button.name == "right" or button.name == "middle") and pressed == False):
	header_locations = ghidra_locations.get_header_locations()
	header_focused = ghidra_locations.get_header_focus()
	focused_window = ghidra_locations.get_focused_window()
	header_focus_set = 0
	#If a header item was clicked, then we will record the action. Otherwise check for click in other location.
	detected_header_click = False
	if(header_focused == ""):
		if(header_locations != {} and y <= header_locations["upper coord"] and y >= header_locations["lower coord"]):
			for header in header_locations:
				if(header == "upper coord" or header == "lower coord"):
					continue
				if(x >= header_locations[header][0] and x <= header_locations[header][1]):
					ghidra_locations.set_header_focus(header)
					log_entry = {"HeaderEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": button_click_type, "X": x, "Y": y,
								 				"Header": header, "MenuItem": None, "SubMenuItem": None, "SecondsInWindow": None, "FocusedWindow": focused_window}}
					json_str = json.dumps(log_entry)
					event_queue.put(json_str, True, 5)	
					header_focus_set = 1
					detected_header_click = True
	else:
		#We know that a header has been clicked on, so some header should be visible right now.
		#Get the sub menu name IF it was set in the "on_move" function
		drop_down_name = ghidra_locations.get_drop_down_name()
		drop_down_Y_boundaries = ghidra_locations.get_header_drop_down_locations(header_focused)
		drop_down_lower_Y = header_locations["upper coord"] + 6 #there is a 6px space between the header and the first drop down.
		drop_down_left_X = header_locations[header_focused][0] + 1 #There is 1px that you can click the header but not the drop down.
		all_header_widths = ghidra_locations.get_header_menu_widths()
		drop_down_right_X = drop_down_left_X + all_header_widths[header_focused]
		#First check the 6 pixels from the header to the start of the drop down. This is a dead zone where nothing happens.
		if(y >= header_locations["upper coord"] and y <= drop_down_lower_Y and x >= drop_down_left_X and x < drop_down_right_X):
			header_focus_set = 1
			detected_header_click = True
		#Check to ensure X & Y coordinates are in the drop down zone. 
		if(y >= drop_down_lower_Y and y <= drop_down_Y_boundaries[len(drop_down_Y_boundaries)-1][1] and
											x >= drop_down_left_X and x < drop_down_right_X):
			drop_down_item = ""
			drop_down_counter = 0
			while(drop_down_counter < len(drop_down_Y_boundaries)):
				if(y > drop_down_Y_boundaries[drop_down_counter][0] and y <= drop_down_Y_boundaries[drop_down_counter][1]):
					drop_down_item = ghidra_locations.header_drop_down_values(header_focused, drop_down_counter)
					#IF the user clicks on an entry with a sub menu, the menu will still be present after the click. KEEP FOCUS!!
					header_sub_drop_down_locations = ghidra_locations.get_header_sub_drop_down_locations()
					if(drop_down_item in header_sub_drop_down_locations):
						header_focus_set = 1
					log_entry = {"HeaderEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": button_click_type, "X": x, "Y": y,
								 				"Header": header_focused, "MenuItem": drop_down_item, "SubMenuItem": None,
								 				"SecondsInWindow": None, "FocusedWindow": focused_window}}
					json_str = json.dumps(log_entry)
					event_queue.put(json_str, True, 5)
					detected_header_click = True
					if(header_focus_set != 1):
						#If we clicked on a real entry then I assume the header drop down is gone. In this event we log a mouse exit event as well.
						drop_down_entry_time = ghidra_locations.get_header_drop_down_entry_time()
						prev_drop_down_item = ghidra_locations.get_current_ghidra_drop_down()
						if(prev_drop_down_item != ""):
							total_time = round(click_time - drop_down_entry_time,7)
							log_entry = {"HeaderEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": "MouseExit", "X": x, "Y": y,
														"Header": header_focused, "MenuItem": prev_drop_down_item, "SubMenuItem": None, 
														"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
							ghidra_locations.set_current_ghidra_drop_down("")
							ghidra_locations.set_header_drop_down_entry_time(-1)
					break
				drop_down_counter += 1
			#NOTE: There is a chance the user clicked on the horizontal line. In this case the focus doesn't change.
			if(drop_down_counter == len(drop_down_Y_boundaries)):
				header_focus_set = 1
				detected_header_click = True
		#The sub menu LEFT clickable boundary is 2 pixels to the right of the right drop down menu.
		elif(drop_down_name != ""):
			header_sub_drop_down_locations = ghidra_locations.get_header_sub_drop_down_locations()
			sub_drop_downs = header_sub_drop_down_locations[drop_down_name]
			drop_down_counter = 0
			while(drop_down_counter < len(sub_drop_downs)):
				if(y > sub_drop_downs[drop_down_counter][0] and y <= sub_drop_downs[drop_down_counter][1]):
					all_sub_menu_widths = ghidra_locations.get_header_sub_menu_widths()
					sub_menu_width = all_sub_menu_widths[header_focused][drop_down_name]
					sub_drop_down_item = ghidra_locations.header_sub_drop_down_values(header_focused, drop_down_name, drop_down_counter)
					#After the Y coordinate is satisfied, check the X coordinates of the sub-menu.
					if(x >= drop_down_right_X + 2 and x <= drop_down_right_X + 2 + sub_menu_width):
						log_entry = {"HeaderEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": button_click_type, "X": x, "Y": y,
													"Header": header_focused, "MenuItem": drop_down_name, "SubMenuItem": sub_drop_down_item,
													"SecondsInWindow": None, "FocusedWindow": focused_window}}
						json_str = json.dumps(log_entry)
						event_queue.put(json_str, True, 5)
						detected_header_click = True
						#Check the mouse entry and exit logs from "on_move" changes.
						prev_sub_menu = ghidra_locations.get_current_ghidra_sub_menu()
						sub_menu_entry_time = ghidra_locations.get_header_sub_menu_entry_time()
						if(prev_sub_menu != ""):
							total_time = round(click_time - sub_menu_entry_time,7)
							log_entry = {"HeaderEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": "MouseExit", "X": x, "Y": y,
														"Header": header_focused, "MenuItem": drop_down_name, "SubMenuItem": prev_sub_menu,
														"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
							ghidra_locations.set_current_ghidra_sub_menu("")
							ghidra_locations.set_header_sub_menu_entry_time(-1)
						break
				drop_down_counter += 1
		#This is a truly obnoxious edge case, if you click ON the left or right edge of the drop down, the drop down doesn't dissapear AND it doesn't register a click.
		if(y >= drop_down_lower_Y and y <= drop_down_Y_boundaries[len(drop_down_Y_boundaries)-1][1]):
			if(x == drop_down_left_X - 1 or x == drop_down_right_X):
				header_focus_set = 1
				detected_header_click = True

	if(not detected_header_click):
		#If we did NOT click on a header, check the coordinates we currently have for all ghidra windows.
		all_ghidra_window_coords = ghidra_locations.get_ghidra_window_coordinates()
		for window_name in all_ghidra_window_coords:
			top_left_coords = all_ghidra_window_coords[window_name][0]
			bottom_right_coords = all_ghidra_window_coords[window_name][1]
			#If one is -1, then they all are. This means we don't have coordinates for this item.
			if(top_left_coords[0] == -1):
				continue				
			if(x >= top_left_coords[0] and x <= bottom_right_coords[0] and y >= top_left_coords[1] and y <= bottom_right_coords[1]):
				#Check to see if we need to change the focus before the log.
				if(window_name != focused_window):
					#When clicking right, middle, or left in decompile or listing windows it will ALWAYS take focus.
					if(window_name == "Decompiler" or window_name == "DisplayListing"):
						ghidra_locations.set_focused_window(window_name)
					elif(button_click_type == "LeftClick" and window_name != "BackButton" and window_name != "ForwardButton"):
						ghidra_locations.set_focused_window(window_name)
					focused_window = ghidra_locations.get_focused_window()
				#In the event the click happened in the function graph, check to see if we know which block it happened in.
				if(window_name == "FunctionGraph"):
					block_event_triggered = False
					function_graph_block_coords = ghidra_locations.get_function_graph_block_coordinates()
					for block_name in function_graph_block_coords:
						block_top_left_coords = function_graph_block_coords[block_name][0]
						block_bot_right_coords = function_graph_block_coords[block_name][1]
						if(x >= block_top_left_coords[0] and x <= block_bot_right_coords[0] and y >= block_top_left_coords[1] and y <= block_bot_right_coords[1]):
							#This is a special print with information 
							log_entry = {"FunctionGraphBlockEvent":{"Timestamp": click_time, "InstrumentationType": "External", "BlockName": block_name,
										 							"EventType": button_click_type, "X": x, "Y": y, "WindowName":window_name, "SecondsInWindow": None,
										 							"FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
							block_event_triggered = True
							break
					#This ensures we always make at least one log message in the event no block was clicked.
					if(not block_event_triggered):
						log_entry = {"WindowEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": button_click_type, "X": x, "Y": y,
													"WindowName":window_name, "SecondsInWindow": None, "FocusedWindow": focused_window}}
						json_str = json.dumps(log_entry)
						event_queue.put(json_str, True, 5)
				else:
					log_entry = {"WindowEvent":{"Timestamp": click_time, "InstrumentationType": "External", "EventType": button_click_type, "X": x, "Y": y,
												"WindowName":window_name, "SecondsInWindow": None, "FocusedWindow": focused_window}}
					json_str = json.dumps(log_entry)
					event_queue.put(json_str, True, 5)
				# If I am going to update with listing view right clicks, it can be here. I am not for these changes due to time constraints.				
				break

	#Every click released will release focus if it isn't in a header entry.
	if(header_focus_set == 0):
		ghidra_locations.set_header_focus("")
		ghidra_locations.set_drop_down_name("")

'''
Parameters:
	x - The X coordinate on the screen of the mouse.
	y - The Y coordinate on the screen of the mouse.
Functionality:
	This tracks mouse movements on the screen. It pulls information from the ghidra_components class to get coordinates of
	all windows and header locations. 

	1) Header is "focused"
		- If a header is focused that means it has been clicked and is showing. If the mouse is in the range of coordinates for the drop 
		  down then we are not tracking time in a window.
		- If the mouse is not in the drop down then it is possible that the mouse can be logging time in windows. This is because you can
		  still use the mouse while the drop down is active, we don't want to miss those actions! Why would someone be hovering outside of the
		  drop down menu anyways!! I have no idea! Perhaps it means something.
	2) Header is not focused.
		- We track for movements through the borders of the ghidra windows that are being monitored. We can go from one window to another, 
		  enter a window, exit a window, or stay in the same state (in a window or not in a window).
		- All of those conditions are checked, in a particular order for correctness, and logs are made accordingly.
Return value:
	N/A

@author Jeremy Johnson
'''
def on_move(x,y):
	global ghidra_locations, event_queue, RELEASE
	#Immediately get the time so that it is as accurate as possible.
	move_time = time.time()	
	focused_window = ghidra_locations.get_focused_window()
	header_focused = ghidra_locations.get_header_focus()

	#Get drop down string values if they were highlighted.
	prev_header_hovered = ghidra_locations.get_current_ghidra_header()
	header_entry_time = ghidra_locations.get_header_entry_time()
	prev_drop_down_item = ghidra_locations.get_current_ghidra_drop_down()
	drop_down_entry_time = ghidra_locations.get_header_drop_down_entry_time()
	prev_sub_menu = ghidra_locations.get_current_ghidra_sub_menu()
	sub_menu_entry_time = ghidra_locations.get_header_sub_menu_entry_time()
	mouse_in_header = False
	mouse_in_drop_down = False
	if(header_focused != ""):
		#This is for header hovering functionality. The user can change headers with out clicking, I monitor for that here.
		header_locations = ghidra_locations.get_header_locations()
		if(header_locations != {} and y <= header_locations["upper coord"] and y >= header_locations["lower coord"]):
			for header in header_locations:
				if(header == "upper coord" or header == "lower coord"):
					continue
				if(x >= header_locations[header][0] and x <= header_locations[header][1]):
					#CAREFUL!! header_focused and prev_header_hovered are in charge of different functionality. DO NOT OVERLAP THE LOGIC!
					#This boolean prevents us from generating "mouse exit" log. We don't return in this case and this provides desired coverage to generate accurate logs.
					mouse_in_header = True
					if(header != prev_header_hovered):
						total_time = round(move_time - header_entry_time,7)
						if(prev_header_hovered != ""):
							log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
														"Header": prev_header_hovered, "MenuItem": None, "SubMenuItem": None,
														"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
						log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseEntry",
													"Header": header, "MenuItem": None, "SubMenuItem": None, "SecondsInWindow": None, "FocusedWindow": focused_window}}
						json_str = json.dumps(log_entry)
						event_queue.put(json_str, True, 5)
						ghidra_locations.set_current_ghidra_header(header)
						ghidra_locations.set_header_entry_time(move_time)
					#Only update and log if this header is not the one currently in focus
					if(header != header_focused):
						ghidra_locations.set_header_focus(header)
						#If by some crazy mouse movement we go from a ghidra window to an entry in the header, clear out the ghidra window stuff.
						current_ghidra_window = ghidra_locations.get_current_ghidra_window()
						if(current_ghidra_window != ""):
							#If we were inside of a window, we are now in the header area. record a "leave" log.
							window_entry_time = ghidra_locations.get_window_entry_time()
							total_time = round(move_time - window_entry_time,7)
							log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
														"WindowName":current_ghidra_window, "SecondsInWindow": total_time, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
							ghidra_locations.set_window_entry_time(-1)
							ghidra_locations.set_current_ghidra_window("")
						return

		#For sub menus, the simple act of putting the mouse in a field with a sub menu activates the sub menu.
		#	- The sub menu automatically dissapears if you hover on a different drop down item, but stays if you're off the drop down area.
		drop_down_name = ghidra_locations.get_drop_down_name()
		header_locations = ghidra_locations.get_header_locations()
		drop_down_Y_boundaries = ghidra_locations.get_header_drop_down_locations(header_focused)
		drop_down_lower_Y = header_locations["upper coord"] + 6 #there is a 6px space between the header and the first drop down.
		drop_down_left_X = header_locations[header_focused][0]
		all_header_widths = ghidra_locations.get_header_menu_widths()
		drop_down_right_X = drop_down_left_X + all_header_widths[header_focused]
	
		#Check to ensure X & Y coordinates are in the drop down zone. Only update the sub-menu variables in this box.
		if(y >= drop_down_lower_Y and y <= drop_down_Y_boundaries[len(drop_down_Y_boundaries)-1][1] and
											x >= drop_down_left_X and x < drop_down_right_X):
			mouse_in_drop_down = True
			drop_down_item = ""
			drop_down_counter = 0
			while(drop_down_counter < len(drop_down_Y_boundaries)):
				if(y > drop_down_Y_boundaries[drop_down_counter][0] and y <= drop_down_Y_boundaries[drop_down_counter][1]):
					#If we are hovering over menus, we don't want to execute code elsewhere.
					current_ghidra_window = ghidra_locations.get_current_ghidra_window()
					if(current_ghidra_window != ""):
						#If we were inside of a window, we are now in the header area. record a "leave" log.
						window_entry_time = ghidra_locations.get_window_entry_time()
						total_time = round(move_time - window_entry_time,7)
						log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
													"WindowName":current_ghidra_window, "SecondsInWindow": total_time, "FocusedWindow": focused_window}}
						json_str = json.dumps(log_entry)
						event_queue.put(json_str, True, 5)
						ghidra_locations.set_window_entry_time(-1)
						ghidra_locations.set_current_ghidra_window("")


					drop_down_item = ghidra_locations.header_drop_down_values(header_focused, drop_down_counter)

					#This is the check to see if we changed which drop down we are on.
					if(drop_down_item != prev_drop_down_item):
						if(prev_drop_down_item != ""):
							total_time = round(move_time - drop_down_entry_time,7)
							log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
														"Header": header_focused, "MenuItem": prev_drop_down_item, "SubMenuItem": None, "SecondsInWindow": total_time, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
						log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseEntry",
													"Header": header_focused, "MenuItem": drop_down_item, "SubMenuItem": None,
													"SecondsInWindow": None, "FocusedWindow": focused_window}}
						json_str = json.dumps(log_entry)
						event_queue.put(json_str, True, 5)
						ghidra_locations.set_current_ghidra_drop_down(drop_down_item)
						ghidra_locations.set_header_drop_down_entry_time(move_time)


					#This is the base case if we already set the drop_down_name, and we barely move the mouse in the entry, it will already be set.
					if(drop_down_name == drop_down_item):
						return
					#Check to see if this drop down item has a sub menu.
					header_sub_drop_down_locations = ghidra_locations.get_header_sub_drop_down_locations()
					if(drop_down_item in header_sub_drop_down_locations):
						ghidra_locations.set_drop_down_name(drop_down_item)
					else:
						ghidra_locations.set_drop_down_name("")
					return
				drop_down_counter += 1


		elif(drop_down_name != ""):
			header_sub_drop_down_locations = ghidra_locations.get_header_sub_drop_down_locations()
			sub_drop_downs = header_sub_drop_down_locations[drop_down_name]
			drop_down_counter = 0
			while(drop_down_counter < len(sub_drop_downs)):
				if(y > sub_drop_downs[drop_down_counter][0] and y <= sub_drop_downs[drop_down_counter][1]):
					all_sub_menu_widths = ghidra_locations.get_header_sub_menu_widths()
					#Very rare error. Happens if the user moves the mouse so fast it jumps to another header with nothing registered inbetween.
					if(header_focused not in all_sub_menu_widths):
						break
					if(drop_down_name not in all_sub_menu_widths[header_focused]):
						break					
					sub_menu_width = all_sub_menu_widths[header_focused][drop_down_name]
					sub_drop_down_item = ghidra_locations.header_sub_drop_down_values(header_focused, drop_down_name, drop_down_counter)
					#After the Y coordinate is satisfied, check the X coordinates of the sub-menu.
					if(x >= drop_down_right_X + 2 and x <= drop_down_right_X + 2 + sub_menu_width):
						mouse_in_drop_down = True
						#If we are hovering over menus, we don't want to continue being "in" another window.
						current_ghidra_window = ghidra_locations.get_current_ghidra_window()
						if(current_ghidra_window != ""):
							#If we were inside of a window, we are now in the header area. record a "leave" log.
							window_entry_time = ghidra_locations.get_window_entry_time()
							total_time = round(move_time - window_entry_time,7)
							log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit", 
														"WindowName":current_ghidra_window, "SecondsInWindow": total_time, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
							ghidra_locations.set_window_entry_time(-1)
							ghidra_locations.set_current_ghidra_window("")
						if(sub_drop_down_item != prev_sub_menu):
							if(prev_sub_menu != ""):
								total_time = round(move_time - sub_menu_entry_time,7)
								log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
															"Header": header_focused, "MenuItem": drop_down_name, "SubMenuItem": prev_sub_menu,
															"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
								json_str = json.dumps(log_entry)
								event_queue.put(json_str, True, 5)
							log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseEntry",
														"Header": header_focused, "MenuItem": drop_down_name, "SubMenuItem": sub_drop_down_item,
														"SecondsInWindow": None, "FocusedWindow": focused_window}}
							json_str = json.dumps(log_entry)
							event_queue.put(json_str, True, 5)
							ghidra_locations.set_current_ghidra_sub_menu(sub_drop_down_item)
							ghidra_locations.set_header_sub_menu_entry_time(move_time)
						#If we are in a sub menu item we do NOT want to perform any additional checks on mouse actions.
						return
				drop_down_counter += 1
	#Any move event that hasn't returned before here means it is no longer hovering on what it previously was. Make an exit log!
	if(prev_header_hovered != "" and not mouse_in_header):
		total_time = round(move_time - header_entry_time,7)
		log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
									"Header": prev_header_hovered, "MenuItem": None, "SubMenuItem": None,
									"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		ghidra_locations.set_current_ghidra_header("")
		ghidra_locations.set_header_entry_time(-1)
	if(header_focused != "" and prev_drop_down_item != ""):
		total_time = round(move_time - drop_down_entry_time,7)
		log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
									"Header": header_focused, "MenuItem": prev_drop_down_item, "SubMenuItem": None,
									"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		ghidra_locations.set_current_ghidra_drop_down("")
		ghidra_locations.set_header_drop_down_entry_time(-1)
	if(header_focused != "" and prev_sub_menu != ""):
		sub_drop_down_values = ghidra_locations.return_sub_drop_down_values()
		found_drop_down = False
		#Loop through the sub menu options and find which drop down we are looking at. It is a sneaky way of getting info not readily available with out a re-design or additional data structure.
		for drop_down_item in sub_drop_down_values[header_focused]:
			for sub_menu_name in sub_drop_down_values[header_focused][drop_down_item]:
				if(sub_menu_name == prev_sub_menu):
					found_drop_down = True
					break
			if(found_drop_down):
				break
		if(not found_drop_down):
			drop_down_item = None
		total_time = round(move_time - sub_menu_entry_time,7)
		log_entry = {"HeaderEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
									"Header": header_focused, "MenuItem": drop_down_item, "SubMenuItem": prev_sub_menu,
									"SecondsInWindow": total_time, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		ghidra_locations.set_current_ghidra_sub_menu("")
		ghidra_locations.set_header_sub_menu_entry_time(-1)

	#We detect the mouse inside the drop down AND the header drop downs are active. No matter what we don't want to check for a new window event.
	if(mouse_in_drop_down and header_focused != ""):
		return
	#There are a few scenarios to consider, we could be in a window then out, out then in, in and in, etc. First, determine if we are in a window or not.
	all_ghidra_window_coords = ghidra_locations.get_ghidra_window_coordinates()
	#This MUST be set to the empty string for my logic. The "current_ghidra_window" is set to the empty string as well and they work together.
	active_window = ""
	for window_name in all_ghidra_window_coords:
		top_left_coords = all_ghidra_window_coords[window_name][0]
		bottom_right_coords = all_ghidra_window_coords[window_name][1]
		if(top_left_coords[0] == -1):
			continue
		if(x >= top_left_coords[0] and x <= bottom_right_coords[0] and y >= top_left_coords[1] and y <= bottom_right_coords[1]):
			active_window = window_name
			break
	current_ghidra_window = ghidra_locations.get_current_ghidra_window()
	window_entry_time = ghidra_locations.get_window_entry_time()
	if(active_window == current_ghidra_window):
		#This is the simple case where nothing has changed and nothing to do.
		return
	elif(active_window == "" and current_ghidra_window != ""):
		#This is the case where the mouse has left the window it was in.
		total_time = round(move_time - window_entry_time,7)
		log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
									"WindowName":current_ghidra_window, "SecondsInWindow": total_time, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		ghidra_locations.set_window_entry_time(-1)
		ghidra_locations.set_current_ghidra_window("")		
	elif(active_window != "" and current_ghidra_window == ""):
		#This is the case where the mouse has entered a window for the first time.
		log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseEntry",
									"WindowName":active_window, "SecondsInWindow": None, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		ghidra_locations.set_window_entry_time(move_time)
		ghidra_locations.set_current_ghidra_window(active_window)
	elif(active_window != current_ghidra_window):
		#This is the case where we went from one ghidra window to the other with nothing in between. I know this because of the previous two checks.
		#First, handle the exit from a ghidra window.
		total_time = round(move_time - window_entry_time,7)
		log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseExit",
									"WindowName":current_ghidra_window, "SecondsInWindow": total_time, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		#Now handle the entry to a new window and update variables.
		log_entry = {"WindowEvent":{"Timestamp": move_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": "MouseEntry",
									"WindowName":active_window, "SecondsInWindow": None, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)
		ghidra_locations.set_window_entry_time(move_time)
		ghidra_locations.set_current_ghidra_window(active_window)
	else:
		if(not RELEASE):
			print("This is logically impossible. just in case, leaving print in for debugging.")

''' 
When focused on header:
	Check if scroll happened IN drop down. If it did, ignore.
		- Get left / right / up / down of furthest coordinates known. if scroll happened in there, lose focus.
Otherwise: Just log which window the scroll happened in.
@author Jeremy Johnson
'''
def on_scroll(x, y, dx, dy):
	global ghidra_locations, event_queue, RELEASE
	scroll_time = time.time()
	focused_window = ghidra_locations.get_focused_window()
	#Get direction of scroll into string
	if(dy == 1):
		scroll_direction = "ScrollUp"
	elif(dy == -1):
		scroll_direction = "ScrollDown"
	else:
		scroll_direction = "Unknown"
	#These are the corners of all windows in ghidra.
	ghidra_window_left_boundary = -1
	ghidra_window_right_boundary = -1
	ghidra_window_top_boundary = -1
	ghidra_window_bot_boundary = -1
	all_ghidra_window_coords = ghidra_locations.get_ghidra_window_coordinates()
	active_window = ""
	for window_name in all_ghidra_window_coords:
		top_left_coords = all_ghidra_window_coords[window_name][0]
		bottom_right_coords = all_ghidra_window_coords[window_name][1]
		if(top_left_coords[0] == -1):
			continue
		if(x >= top_left_coords[0] and x <= bottom_right_coords[0] and y >= top_left_coords[1] and y <= bottom_right_coords[1]):
			active_window = window_name
		#Check all of the coordinates to find the edges. Used to determine if scroll is destructive to the header drop menu or not.
		if(ghidra_window_left_boundary == -1 or ghidra_window_left_boundary > top_left_coords[0]):
			ghidra_window_left_boundary = top_left_coords[0]
		if(ghidra_window_right_boundary == -1 or ghidra_window_right_boundary < bottom_right_coords[0]):
			ghidra_window_right_boundary = bottom_right_coords[0]
		if(ghidra_window_top_boundary == -1 or ghidra_window_top_boundary > top_left_coords[1]):
			ghidra_window_top_boundary = top_left_coords[1]
		if(ghidra_window_bot_boundary == -1 or ghidra_window_bot_boundary < bottom_right_coords[1]):
			ghidra_window_bot_boundary = bottom_right_coords[1]
	#For scrolling we have to consider if scroll happened in a drop down, or in a window. 
	#If a drop down is active then the drop down can be cancelled by this scroll.
	header_focused = ghidra_locations.get_header_focus()
	if(header_focused != ""):
		#For sub menus, the simple act of putting the mouse in a field with a sub menu activates the sub menu.
		#	- The sub menu automatically dissapears if you hover on a different drop down item, but stays if you're off the drop down area.
		drop_down_name = ghidra_locations.get_drop_down_name()
		header_locations = ghidra_locations.get_header_locations()
		drop_down_Y_boundaries = ghidra_locations.get_header_drop_down_locations(header_focused)
		drop_down_lower_Y = header_locations["upper coord"] + 6 #there is a 6px space between the header and the first drop down.
		drop_down_left_X = header_locations[header_focused][0]
		all_header_widths = ghidra_locations.get_header_menu_widths()
		drop_down_right_X = drop_down_left_X + all_header_widths[header_focused]
		#Check to ensure X & Y coordinates are in the drop down zone. Only update the sub-menu variables in this box.
		if(y >= drop_down_lower_Y and y <= drop_down_Y_boundaries[len(drop_down_Y_boundaries)-1][1] and
											x >= drop_down_left_X and x < drop_down_right_X):
			#Scroll detected in drop down, ignore this.
			return
		elif(drop_down_name != ""):
			header_sub_drop_down_locations = ghidra_locations.get_header_sub_drop_down_locations()
			sub_drop_downs = header_sub_drop_down_locations[drop_down_name]
			drop_down_counter = 0
			while(drop_down_counter < len(sub_drop_downs)):
				if(y > sub_drop_downs[drop_down_counter][0] and y <= sub_drop_downs[drop_down_counter][1]):
					all_sub_menu_widths = ghidra_locations.get_header_sub_menu_widths()
					sub_menu_width = all_sub_menu_widths[header_focused][drop_down_name]
					sub_drop_down_item = ghidra_locations.header_sub_drop_down_values(header_focused, drop_down_name, drop_down_counter)
					#After the Y coordinate is satisfied, check the X coordinates of the sub-menu.
					if(x >= drop_down_right_X + 2 and x <= drop_down_right_X + 2 + sub_menu_width):
						#Scroll detected in drop down, ignore this.
						return						
				drop_down_counter += 1
		#This is a truly obnoxious edge case, if you click ON the left or right edge of the drop down, the drop down doesn't dissapear AND it doesn't register a click.
		if(y >= drop_down_lower_Y and y <= drop_down_Y_boundaries[len(drop_down_Y_boundaries)-1][1]):
			if(x == drop_down_left_X - 1 or x == drop_down_right_X):
				#Scroll detected in drop down, ignore this.				
				return
		#Scroll did NOT happen in the drop downs. So do we have to reset the focus? Depends if it took place in the ghidra GUI boundaries.
		if(x >= ghidra_window_left_boundary and x <= ghidra_window_right_boundary and y <= ghidra_window_bot_boundary and y >= ghidra_window_top_boundary):
			#Scroll happened in the ghidra gui boundary. Cancel the drop down!
			ghidra_locations.set_header_focus("")
			ghidra_locations.set_drop_down_name("")
			#Do NOT return here. We want to log the scroll action and the window it happened in.
	if(active_window != ""):
		#Scroll was detected in a known window. Log it!
		log_entry = {"ScrollEvent":{"Timestamp": scroll_time, "InstrumentationType": "External", "X": x, "Y": y, "EventType": scroll_direction,
									"WindowName":active_window, "FocusedWindow": focused_window}}
		json_str = json.dumps(log_entry)
		event_queue.put(json_str, True, 5)

'''
This is the function that kicks everything off. The first class created is ghidra_windows, this is used to
keep track of all aspects in ghidra. Code can be found in ghidra_components.py.

We then create the LslLogger class, this handles logging to our log file and using the Lab Streaming Layer (LSL). One
key tennet of the logging in this program is that each action is associated with an item in ghidra. We always include
a header item, window name, etc in each log so each action can be associated with some meaning in ghidra.

Lastly we create a class for monitoring borders in ghidra. This class verifies the borders of ghidra have not changed
or closed. We verify every XX seconds using openCV, numpy, and pools for speed. 

"Listener" acts like a queue, with each action that happens being added to the back of the queue. 
So if you click, move your mouse, then click, the items are guaranteed to be processed in that order. This blocks 
the function from exiting and is constantly listening for new actions.

@author Jeremy Johnson
'''
def main():
	global ghidra_locations, event_queue, RELEASE
	#This queue is used to communicate events between threads.
	event_queue = multiprocessing.Queue()
	#For mapping out all ghidra locations.
	ghidra_locations = ghidra_windows(RELEASE)
	#For logging locally and sending data via UDP.
	event_logger = EventLogger(event_queue, __file__, log_path)
	#For monitoring changes in window sizes or starting / stopping ghidra.
	ghidra_monitor = monitor_ghidra_borders(ghidra_locations, event_queue)
	graph_block_monitor = monitor_graph_blocks(ghidra_locations, event_queue)

	lsl_logging_thread = threading.Thread(name='event_logger', target=event_logger.expel_and_log_data)
	ghidra_monitor_thread = threading.Thread(name='ghidra_monitor', target=ghidra_monitor.monitor_ghidra_locations)
	graph_block_monitor_thread = threading.Thread(name='graph_blocks', target=graph_block_monitor.monitor_ghidra_graph_blocks)

	lsl_logging_thread.start()
	ghidra_monitor_thread.start()
	graph_block_monitor_thread.start()
	#This blocks the process from ending, monitors the actions I specify in the Listener(..) function call.
	with Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll) as listener:
		listener.join()

if(__name__ == "__main__"):
	main()


'''
NOTES:
For the Decompile:
	- The bottom right is going to be hard to pin down quickly. It could have no arrows,
		a right arrow, a down arrow, or both arrows. 
		-> Currently, short of going C -> X -> (if up arrow close -> find down arrow) (check for right arrow / no arrows)
		-> Is it possible to get pixel perfect screen shot with no white above, with top line of dark pixels? the top line stops on the right angle change, might be enought to line up with the X..
'''
