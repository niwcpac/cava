package cavalistener;

import java.awt.Component;
import java.util.EventListener;

import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import ghidra.app.util.viewer.listingpanel.ListingPanel;

/**
 * Utilities for instrumenting Ghidra user interface components.
 * 
 * @author Sunny J. Fugate
 */
public final class CavaUtils {

	/**
	 * Search for a JComponent within the provided component list by class 
	 * 
	 * @param 	clazz 		the class of the desired component
	 * @param 	components	an array of AWT Components
	 * @return 				the first instance of the indicated JComponent class or null if no instance is found
	 */
	public static JComponent findJComponentByClass(Class<?> clazz , Component[] components) {
		JComponent found=null;
		
		for(int i=0;i< components.length;i++) {
			if(components[i].getClass() != clazz) {
				continue;
			}
			found=(JComponent)components[i];
			break;
		}
		return found;
	}
	
	/**
	 * Search for a listener of the provided type extending EventListener
	 * NOTE: it might be better to use the class itself rather than its name
	 * 
	 * @param 	listeners	an array of event listeners
	 * @param 	className	the name of the listener class
	 * @return				true if an event listener with the same class name is found
	 */
	public static boolean hasEventListener(EventListener[] listeners, String className) {
		for(EventListener listener : listeners) {
			String listenerClassName = listener.getClass().getName();
			if(listenerClassName.equals(className)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Instrument a ListingPanel by attaching mouse and JScrollBar adjustment listeners to its Swing and AWT 
	 * components.  Instrumentation should be idempotent, meaning that calling this function can be 
	 * done multiple time and result in the same effect.  This is handled by the CavaEventListener class
	 * by maintaining a list of instrumented objects and attached listeners. 
	 * 
	 * The following is a direct, but potentially brittle way of fetching components from the Swing
	 * AWT component hierarchy.  Since these components are not exposed directly
	 * in public methods, this seems like the only easy way of getting access. 
	 * It is also fairly generic, so can be applied easily to dig into 
	 * whatever buttons/sliders/etc that we want to attach event listeners
	 * to. 
	 * 
	 * A limitation of this simplistic approach is that it may not work well (or at all) for
	 * dynamically generated components.  A more robust approach may be to test component property/existence and then recurrently
     * re-create the initializer until the component is ready.  This may also work for 
	 * dynamic instrumentation where we are waiting for a component to be created/instantiated
	 * based on user interactions and may also be handled in the plug-in by recursively calling this 
	 * function with a delay until it succeeds. 
	 * 
	 * This method currently handles variations in the ListingView where the view can be split. 
	 * The instrumentation is relatively limited, handling the following types of user interaction: 
	 * 
	 * - Mouse Entry/Exit to the ListingPanel
	 * - Vertical and Horizontal scrolling 
	 * - Mouse interactions with Listing view "Fields" such as entry/exit, location, selection, and input
	 * 
	 * NOTE: The following instrumentation still needs to be added:
	 * - mouse hover events
	 * - right clicks on fields
	 * 
	 * @param 	cavaComponentName	the name of the CAVA plug-in being instrumented (used to label the source of emitted CAVA events)
	 * @param 	listingPanel		the outer ListingPanel being instrumented
	 * @return						true if the instrumentation was successful (no errors or exceptions)
	 */
	public static boolean instrumentListingView(String cavaComponentName, ListingPanel listingPanel, boolean ignoreScrolling) {
		if(listingPanel == null) { return false; }
		
		/*
		 * The AWT Component tree is built and will change at runtime.  
		 * In order to prevent this thread's 
		 * interactions from being adversely affected, we 
		 * use a 'synchronized' block over the component tree. 
		 * This has performance implications, but is likely to be necessary. 
		 */
		synchronized(listingPanel.getTreeLock()) {
			
			//-----------------------------------------------------------
			// Instrument the ListPanel
			// We will be digging either two or three layers deep in the AWT component hierarchy
			// depending on whether the ListingPanel contains a JSplitPane or not
			Component[] clist = listingPanel.getComponents();
			Component[] clist2 = clist; //default is to directly use ListingPanel (no JSplitPane)
			Component[] clist3;
			
			//If the ListingView instance contains a JSplitPane, then use its components rather than its parent's
			JSplitPane jSplitPane = (JSplitPane)CavaUtils.findJComponentByClass(JSplitPane.class, clist);
			if(jSplitPane != null) { clist2 = jSplitPane.getComponents(); }
			
			
			//Instrument scrolling unless we are told not to (i.e. Function Graph produced phantom scroll events during graph manipulation)
			if(!ignoreScrolling) {
				IndexedScrollPane indexedScrollPane = (IndexedScrollPane)CavaUtils.findJComponentByClass(IndexedScrollPane.class,clist2);
				if(indexedScrollPane == null) { return false; }
			
				clist3 = indexedScrollPane.getComponents();
				JScrollPane jScrollPane = (JScrollPane)CavaUtils.findJComponentByClass(JScrollPane.class,clist3); 
				if(jScrollPane == null) { return false; }
				
	
				//Instrument JScrollPane scroll adjustments
				CavaEventListener.instrumentHorizontalScrollbarAdjustment(cavaComponentName, jScrollPane.getHorizontalScrollBar());
				CavaEventListener.instrumentVerticalScrollbarAdjustment(cavaComponentName, jScrollPane.getVerticalScrollBar());
			}
			
			//-----------------------------------------------------------
			// Instrument the FieldPanel
			FieldPanel fieldPanel = listingPanel.getFieldPanel();
			if(fieldPanel == null) { return false; }
			
			//Instrument mouse interaction listener so it captures initial entry into the ListingPanel's top-level component
			CavaEventListener.instrumentMouseInteraction(cavaComponentName, fieldPanel);
			
			// Add listeners for field interaction events
			CavaEventListener.instrumentFieldMouse(cavaComponentName, fieldPanel);
			CavaEventListener.instrumentFieldLocation(cavaComponentName, fieldPanel);
			CavaEventListener.instrumentFieldSelection(cavaComponentName, fieldPanel);
			CavaEventListener.instrumentFieldInput(cavaComponentName, fieldPanel);
		}
		return true;
	}
}
