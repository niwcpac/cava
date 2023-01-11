package cavalistener;

import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.math.BigInteger;
import java.util.EventListener;
import java.util.HashMap;

import javax.swing.JComponent;
import javax.swing.JScrollBar;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.FieldInputListener;
import docking.widgets.fieldpanel.listener.FieldLocationListener;
import docking.widgets.fieldpanel.listener.FieldMouseListener;
import docking.widgets.fieldpanel.listener.FieldSelectionListener;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;


/**
 * Abstract base class for various CAVA event listeners. 
 * 
 * Class also holds factory methods for generating new listeners of various types.
 * 
 * A key problem with instrumenting components in Ghidra is that many are constructed 
 * on an "as needed" basis.  For example, the decompiler plugin only generates 
 * its views on request.  This means that we need to dynamically detect and then
 * inject instrumentation to these components after they are constructed. 
 * 
 * This class makes an attempt to track and  
 * store a global reference for every instrumented object to 
 * the set of listener classes attached.  
 * This presumes that is desirable to only instrument each object once and only once.
 * 
 * The problem that this addresses is that not all Ghidra components 
 * have public methods for determining which custom listeners are attached. 
 * 
 * For example, the FieldPanel stores various lists for listeners, 
 * but does not provide a public interface. 
 * 
 * NOTE: the hash set may grow large if we never remove items...
 * Since we are not informed of when objects are disposed along with their listeners.
 * 
 * This could also potentially result in memory leaks if we retain a reference
 * to the listener even after the original item associated with the listener was destroyed. 
 * 
 * Future work: test objects in HashMap to determine their disposition. 
 * 
 * @author Sunny Fugate
 */
public abstract class CavaEventListener implements EventListener {
	public String eventSource;
	

	static final HashMap<Object,HashMap<String,Object>> listenerMap = new HashMap<Object,HashMap<String,Object>>(); //TODO: specify types/generics?
	
	public CavaEventListener(String _eventSource) {
		this.eventSource=_eventSource;
	}
	
	
	/**
	 * Returns whether the listener map contains
	 * an event listener of the specified class for the given object. 
	 * 
	 * @param obj the component we are interested in instrumenting
	 * @param clazz the class of a listener
	 * 
	 * @return true if the listenerMap contains the object its hashset contains the class
	 */
	static boolean listenerMapContains(Object obj, String className) {
		if(listenerMap.containsKey(obj)) {
			HashMap<String, Object> mapOfClasses = listenerMap.get(obj);
			if(mapOfClasses.containsKey(className)) { return true; }
		}
		return false;
	}
	
	/**
	 * Adds the specified listener class to the HashSet for the Object.
	 * 
	 * @param obj the object
	 * @param clazz the class of the listener
	 */
	static void addToListenerMap(Object obj, Object listener) { 
		HashMap<String, Object> mapOfClasses;
		String className = listener.getClass().getName();
		
		if(listenerMap.containsKey(obj)) {
			mapOfClasses = listenerMap.get(obj);
			//TODO: we may inadvertently overwrite prior references...
			
			mapOfClasses.put(className, listener);
		} else { //We've not seen this class of listener for this specific object yet
			mapOfClasses = new HashMap<String, Object>();
			mapOfClasses.put(className, listener);
			listenerMap.put(obj, mapOfClasses);
		}
	}
	
	/**
	 * Adds an AdjustmentListener to a JScrollBar. 
	 * 
	 * If called multiple times, it should be idempotent, ignoring components for which there is already
	 * instrumentation attached. 
	 * 
	 * @param _eventSource
	 * @param jScrollBar
	 */
	public static void instrumentVerticalScrollbarAdjustment(String _eventSource, JScrollBar jScrollBar) {
		String className = CavaVerticalScrollbarAdjustmentListener.class.getName();
		
		//Check if the actual component has a listener
		if(CavaUtils.hasEventListener(jScrollBar.getAdjustmentListeners(), className)) { return; }
		
		CavaVerticalScrollbarAdjustmentListener listener = new CavaVerticalScrollbarAdjustmentListener(_eventSource);
		jScrollBar.addAdjustmentListener(listener);
		addToListenerMap(jScrollBar, listener);
	}
	
	/**
	 * Adds an AdjustmentListener to a JScrollbar
	 * @param _eventSource
	 * @param jScrollBar
	 */
	public static void instrumentHorizontalScrollbarAdjustment(String _eventSource, JScrollBar jScrollBar) {
		String className = CavaHorizontalScrollbarAdjustmentListener.class.getName();
		
		if(CavaUtils.hasEventListener(jScrollBar.getAdjustmentListeners(), className)) { return; }
		
		CavaHorizontalScrollbarAdjustmentListener listener = new CavaHorizontalScrollbarAdjustmentListener(_eventSource);
		
		jScrollBar.addAdjustmentListener(listener);
		addToListenerMap(jScrollBar, listener);
	}
	
	/**
	 * Instrument mouse interactions with the component.
	 * 
	 * @param _eventSource
	 * @param component
	 */
	public static void instrumentMouseInteraction(String _eventSource, JComponent component) {
		String className = CavaMouseListener.class.getCanonicalName();
		
		//TODO: probably should combine the two methods for determining component listener attachment...
		if(CavaUtils.hasEventListener(component.getMouseListeners(), className)) { return; }
		
		CavaMouseListener listener = new CavaMouseListener(_eventSource);
		component.addMouseListener(listener);
		addToListenerMap(component, listener);
	}
	
	/**
	 * Instrument the mouse wheel for the component.
	 * 
	 * @param _eventSource
	 * @param component
	 */
	public static void instrumentMouseWheel(String _eventSource, JComponent component) {		
		String className = CavaMouseWheelListener.class.getCanonicalName();
		
		if(CavaUtils.hasEventListener(component.getMouseListeners(), className)) { return; }
		CavaMouseWheelListener listener = new CavaMouseWheelListener(_eventSource);
		component.addMouseWheelListener(listener);
		addToListenerMap(component, listener);
	}
	
	/**
	 * Instrument mouse motion for the component.
	 * 
	 * @param _eventSource
	 * @param component
	 */
	public static void instrumentMouseMotion(String _eventSource, JComponent component) {		
		String className = CavaMouseMotionListener.class.getCanonicalName();
		
		if(CavaUtils.hasEventListener(component.getMouseListeners(), className)) { return; }
		CavaMouseMotionListener listener = new CavaMouseMotionListener(_eventSource);
		component.addMouseMotionListener(listener);
		addToListenerMap(component, listener);
	}
	
	/**
	 * Instrument mouse interactions with a Listing View field.
	 * 
	 * @param _eventSource
	 * @param fieldPanel
	 */
	public static void instrumentFieldMouse(String _eventSource, FieldPanel fieldPanel) {
		String className = CavaFieldMouseListener.class.getCanonicalName();
		
		//Field listener lists are not available to us.. use our internal lookup table
		if(listenerMapContains(fieldPanel, className)) { return; }
		
		CavaFieldMouseListener listener = new CavaFieldMouseListener(_eventSource);
		fieldPanel.addFieldMouseListener(listener);
		addToListenerMap(fieldPanel, listener);
	}
	
	/**
	 * Instrument locations associated with a Listing View field.
	 * 
	 * @param _eventSource
	 * @param fieldPanel
	 */
	public static void instrumentFieldLocation(String _eventSource, FieldPanel fieldPanel) {		
		String className = CavaFieldLocationListener.class.getName();
		
		//Field listener lists are not available to us.. use our internal lookup table
		if(listenerMapContains(fieldPanel, className)) { return; }
		
		CavaFieldLocationListener listener = new CavaFieldLocationListener(_eventSource);
		fieldPanel.addFieldLocationListener(listener);
		addToListenerMap(fieldPanel, listener);
	}
	
	/**
	 * Instrument selection of Listing View field columns and rows.
	 * 
	 * @param _eventSource
	 * @param fieldPanel
	 */
	public static void instrumentFieldSelection(String _eventSource, FieldPanel fieldPanel) {
		String className = CavaFieldSelectionListener.class.getName();
		
		//Field listener lists are not available to us.. use our internal lookup table
		if(listenerMapContains(fieldPanel, className)) { return; }
		
		CavaFieldSelectionListener listener = new CavaFieldSelectionListener(_eventSource);
		fieldPanel.addFieldSelectionListener(listener);
		addToListenerMap(fieldPanel, listener);
	}
	
	/**
	 * Instrument keyboard input into a Listing View field.
	 * 
	 * @param _eventSource
	 * @param fieldPanel
	 */
	public static void instrumentFieldInput(String _eventSource, FieldPanel fieldPanel) {
		String className = CavaFieldInputListener.class.getName();
		
		//Field listener lists are not available to us.. use our internal lookup table
		if(listenerMapContains(fieldPanel, className)) { return; }
		
		CavaFieldInputListener listener = new CavaFieldInputListener(_eventSource);
		fieldPanel.addFieldInputListener(listener);
		addToListenerMap(fieldPanel, listener);
	}
}


//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
// Event Listener implementations follow
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------

/**
 * This class handles field locations.
 * 
 * @author Sunny Fugate
 */
class CavaFieldLocationListener extends CavaEventListener implements FieldLocationListener {
	FieldLocation location;
	Field field;
	EventTrigger trigger;
	
	public CavaFieldLocationListener(String _eventSource) {
		super(_eventSource);
	}

	@Override
	public void fieldLocationChanged(FieldLocation _location, Field _field, EventTrigger _trigger) {
		this.location=_location;
		this.field=_field;
		this.trigger=_trigger;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateFieldLocationEvent(this.eventSource, this.location, this.field, this.trigger);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}

/**
 * This class handles mouse interactions with fields. 
 * 
 * @author Sunny Fugate
 */
class CavaFieldMouseListener extends CavaEventListener implements FieldMouseListener {
	FieldLocation location;
	Field field;
	MouseEvent event;
	
	public CavaFieldMouseListener(String _eventSource) {
		super(_eventSource);
	}

	@Override
	public void buttonPressed(FieldLocation _location, Field _field, MouseEvent _event) {
		this.location=_location;
		this.field=_field;
		this.event=_event;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateFieldMouseEvent(this.eventSource, this.location, this.field, this.event);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}

/**
 * This class handles field selection events. 
 * 
 * @author Sunny Fugate
 */
class CavaFieldSelectionListener extends CavaEventListener implements FieldSelectionListener {
	FieldSelection selection;
	EventTrigger trigger;
	
	public CavaFieldSelectionListener(String _eventSource) {
		super(_eventSource);
	}

	@Override
	public void selectionChanged(FieldSelection _selection, EventTrigger _trigger) {
		this.selection=_selection;
		this.trigger=_trigger;
		
		//Do not emit event if the selection is empty
		//TODO: determine if this makes sense...
		if(selection.getNumRanges()==0) { return; }
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateFieldSelectionEvent(this.eventSource, this.selection, this.trigger);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}

/**
 * This class handles field input from a keyboard. 
 * 
 * @author Sunny Fugate
 */
class CavaFieldInputListener extends CavaEventListener implements FieldInputListener {
	KeyEvent keyEvent;
	BigInteger index;
	int fieldNum;
	int row;
	int col;
	Field field;
	
	public CavaFieldInputListener(String _eventSource) {
		super(_eventSource);
	}


	@Override
	public void keyPressed(KeyEvent _keyEvent, BigInteger _index, int _fieldNum, int _row, int _col, Field _field) {
		keyEvent=_keyEvent;
		index=_index;
		fieldNum=_fieldNum;
		row=_row;
		col=_col;
		field=_field;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateFieldInputEvent(eventSource, keyEvent, index, fieldNum, row, col, field);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}

/**
 * This class handles vertical scrollbar adjustments
 * @author Sunny J. Fugate
 */
class CavaVerticalScrollbarAdjustmentListener extends CavaEventListener implements AdjustmentListener {
	int value;
	
	public CavaVerticalScrollbarAdjustmentListener(String _eventSource) {
		super(_eventSource);
	}
	
	@Override
	public void adjustmentValueChanged(AdjustmentEvent event) {
		this.value=event.getValue();	
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateVerticalScrollbarAdjustmentEvent(this.eventSource, event, this.value);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}

/**
 * This class handles horizontal scrollbar adjustments.
 * 
 * @author Sunny J. Fugate
 */
class CavaHorizontalScrollbarAdjustmentListener extends CavaEventListener implements AdjustmentListener {
	int value;
	
	public CavaHorizontalScrollbarAdjustmentListener(String _eventSource) {
		super(_eventSource);
	}
	
	@Override
	public void adjustmentValueChanged(AdjustmentEvent event) {
		this.value=event.getValue();	
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateHorizontalScrollbarAdjustmentEvent(this.eventSource, event, this.value);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}


/**
 * Class to handle mouse interactions.
 * 
 * @author Sunny Fugate
 */
class CavaMouseListener extends CavaEventListener implements MouseListener  {
	MouseEvent event;
	
	public CavaMouseListener(String _eventSource) {
		super(_eventSource);
	}
	
	@Override
	public void mouseClicked(MouseEvent e) {
		this.event=e;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateMouseClickedEvent(this.eventSource, event);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
	
	@Override
	public void mousePressed(MouseEvent e) {
		this.event=e;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateMousePressedEvent(this.eventSource, event);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
	
	@Override
	public void mouseReleased(MouseEvent e) {
		this.event=e;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateMouseReleasedEvent(this.eventSource, event);
		CavaEventPublisher.publishNewEvent(ghidraEvent);

	}
	@Override
	public void mouseEntered(MouseEvent e) {
		this.event=e;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateMouseEnteredEvent(this.eventSource, event);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
	
	@Override
	public void mouseExited(MouseEvent e) {
		this.event=e;
		
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateMouseExitedEvent(this.eventSource, event);
		CavaEventPublisher.publishNewEvent(ghidraEvent);
	}
}


/**
 * Class to handle mouse wheel interactions.  This class is not yet implemented, but provided as a placeholder. 
 * 
 * @author Sunny Fugate
 */
class CavaMouseWheelListener extends CavaEventListener implements MouseWheelListener {
	
	public CavaMouseWheelListener(String _eventSource) {
		super(_eventSource);
	}

	@Override
	public void mouseWheelMoved(MouseWheelEvent e) {
		System.out.println("NOT IMPLEMENTED: (CavaEventListener.CavaMouseWheelListener) MouseWheel: "+e.toString());
	}
}

/**
 * Class to handle mouse motion. This class is not yet implemented, but provided as a placeholder. 
 * @author Sunny Fugate
 */
class CavaMouseMotionListener extends CavaEventListener implements MouseMotionListener {
	
	public CavaMouseMotionListener(String _eventSource) {
		super(_eventSource);
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		System.out.println("NOT IMPLEMENTED (CavaEventListener.CavaMouseMotionListener): MouseDragged: "+e.toString());
	}
	
	@Override 
	public void mouseMoved(MouseEvent e) {
		System.out.println("NOT IMPLEMENTED (CavaEventListener.CavaMouseMotionListener): MouseMoved: "+e.toString());

	}
}
