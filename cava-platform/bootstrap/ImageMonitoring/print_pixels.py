'''
prints the pixel coordinates of the mouse. Useful for debugging!
@author Jeremy Johnson
'''
from pynput.mouse import Listener
def on_move(x,y):
	print(x,y)
with Listener(on_move=on_move) as listener:
	listener.join()