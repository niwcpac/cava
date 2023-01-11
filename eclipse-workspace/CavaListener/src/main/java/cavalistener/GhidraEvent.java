package cavalistener;

import java.awt.AWTEvent;
import java.awt.event.AdjustmentEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;



/**
 * Base class for GhidraEvents to hold event data relevant for the CAVA
 * instrumentation and HSR experiments.  
 * 
 * Member classes should call super() to take advantage of any common
 * fields such as timestamp format or other common data. 
 *  
 * Note: The Jackson JSON library seems to have issues with capitalized field names, introducing duplicates due to 
 * reliance on presumption of camel-case getter/setter and lowercase field names.
 * See: https://github.com/FasterXML/jackson-databind/issues/1609
 * 
 * Jackson also has issues with private events without any getters. This 
 * will cause private variables to not be serialized. That's why we have two programName variables.
 * One is used for Jackson to serialize the program name and the static variable is used to hold 
 * the program name. That way, we can set it at object construction.
 * 
 * As a result, we have to manually annotate property names if we want a different format.
 * 
 * All implementations should either use Jackson Annotations or limit public 
 * fields to plain old java objects. Ghidra objects (e.g. Address)
 * tend to be poor examples of traditional Java as they tend to have recursive data structures.
 * It is recommended to perform translation of these types to simpler forms as needed for serialization.
 * 
 * @author Sunny J. Fugate
 *
 * @param GhidraEvent<T>
 */
public abstract class GhidraEvent<T> {
	//Jackson JSON object mapper
	private static ObjectMapper mapper = new ObjectMapper();
	
	@JsonProperty("Timestamp")
	private BigDecimal timestamp;
	
	@JsonProperty("InstrumentationType")
	private final String instrumentationType="Internal";
	
	@JsonProperty("EventSequenceNumber")
	private int eventSequenceNumber;
	
	@JsonProperty("EventSource")
	private String eventSource;
	
	@JsonProperty("EventName")
	private String eventName;
	
	@JsonProperty("EventType")
	private GhidraEventType eventType;
	
	@JsonProperty("EventTrigger")
	private String eventTrigger;
	
	@JsonProperty("ProgramName")
	private String programName=null;
	
	/* 
	 * We need a private static to use a global, bug this global cannot be 
	 * used to create our JSON event due to serialization errors (-Froy)
	 */
	private static String _programName=null;
	
	@JsonProperty("TaskID")
	private int taskID=0;
	
	@JsonProperty("TrialID")
	private int trialID=0;
	
	@JsonProperty("TaskUUID")
	private String taskUUID="";

	
	/**
	 * Instantiate a Ghidra Event
	 * 
	 * @param ghidraEventType
	 * @param eventSource
	 * @param event
	 */
	public GhidraEvent(GhidraEventType ghidraEventType, String eventSource, AWTEvent event) {
		initEvent();
		
		this.eventType=ghidraEventType;
		this.eventName=ghidraEventType.getName();
		this.eventSource=eventSource;
		
		if(event!=null) {
			this.eventTrigger=event.getClass().getSimpleName();
		}
		
		this.programName=GhidraEvent._programName;
	}
	
	
	/**
	 * Instantiate a Ghidra Event
	 * 
	 * @param ghidraEventType
	 * @param eventSource
	 * @param eventTrigger
	 */

	public GhidraEvent(GhidraEventType ghidraEventType, String eventSource, EventTrigger eventTrigger) {
		initEvent();
		
		this.eventType=ghidraEventType;
		this.eventName=ghidraEventType.getName();
		this.eventSource=eventSource;
		this.eventTrigger=eventTrigger.name();
		
		this.programName=GhidraEvent._programName;
	}
	
	/**
	 * Instantiate a Ghidra Event
     *
	 * @param ghidraEventType
	 * @param eventSource
	 * @param pluginEvent
	 */
	public GhidraEvent(GhidraEventType ghidraEventType, String eventSource, PluginEvent pluginEvent) {
		initEvent();
		
		this.eventType=ghidraEventType;
		this.eventName=ghidraEventType.getName();
		this.eventSource=eventSource;
		this.eventTrigger=pluginEvent.getEventName();
		
		this.programName=GhidraEvent._programName;
	}
	
	/**
	 * Instantiate a Ghidra Event
	 * 
	 * @param ghidraEventType
	 * @param pluginEvent
	 */
	public GhidraEvent(GhidraEventType ghidraEventType, PluginEvent pluginEvent) {
		initEvent();
		
		this.eventType=ghidraEventType;
		this.eventSource=pluginEvent.getSourceName();
		
		//Note that all plugin generated events are generated via internal, inter-plugin communication
		this.eventTrigger=EventTrigger.INTERNAL_ONLY.name();
		
		this.eventName=ghidraEventType.getName();
		
		//If this is an unhandled plugin event, stuff in its name so we know what it is
		if(this.eventType==GhidraEventType.GHIDRA_UNHANDLED_PLUGIN_EVENT) {
			this.eventName=pluginEvent.getEventName();
		}
				
		
		/* 
		 * Set the program name so that it will appear with *all* produced events. 
		 * 
		 * If the new event is a ProgramActivatePluginEvent then update
		 * the global reference to the loaded program.
		 *   
		 * NOTE: this somewhat assumes that we only have a single program loaded. 
		 * While this *should* be updated when a user switches tabs when two programs 
		 * are loaded, if this event is not produced, then this may mismatch the program
		 * which is actually being interacted with. 
		 */
		if(pluginEvent instanceof ProgramActivatedPluginEvent) {
			//Default is a null program, or none loaded
			Program newProgram = null;
			String newProgramName = null;
			ProgramActivatedPluginEvent programActivatedPluginEvent = (ProgramActivatedPluginEvent)pluginEvent;
			if(programActivatedPluginEvent != null) { 
				newProgram = programActivatedPluginEvent.getActiveProgram();
				if(newProgram != null) {
					newProgramName = newProgram.getName();
				}
			}
			
			//The program name may have been updated, use the value of the plugin event
			GhidraEvent._programName = newProgramName;	
			this.programName = newProgramName;
		} else {
			//Use the current global program name for this event
			this.programName = _programName;
		}
		
		
	}
	
	
	/**
	 * Initialize an event, setting the Unix time of event creation to the current time
	 */
	private void initEvent() {
		Instant now = Instant.now(); //Epoch Time
		long sec=now.getEpochSecond(); //Seconds
		int nano=now.getNano(); //Nanoseconds
		double nano_float=(double)(nano)/1_000_000_000;
		
		//Store in a manner to preserve desired scale of 6 decimal places
		this.timestamp = new BigDecimal(sec+nano_float).setScale(7, RoundingMode.HALF_DOWN);
	}
	
	/**
	 * Override the event's type for event subclasses. 
	 * 
	 * @param ghidraEventType
	 */
	protected void overrideEventType(GhidraEventType ghidraEventType) {
		this.eventType=ghidraEventType;
	}
	
	/**
	 * The call to toJSON should not be called during queuing or dequeuing by
	 * any internal Ghidra thread.  This should be handled asynchronously 
	 * when data is meant to be transmitted or for debugging. 
	 * 
	 * @return String representation of the JSON data structure of this event
	 */
	public static String toJSON(GhidraEvent<?> event) {
		try {
			String jsonString = mapper.writeValueAsString(event);
			return jsonString;
		} catch(JsonProcessingException e) {
			System.out.println(e.getMessage());
		}
		return null;
	}
	
	/**
	 * Returns a formatted JSON string.
	 * 
	 * @return a formatted string representation of the JSON data structure of this event
	 */
	public static String toPrettyPrintJSON(GhidraEvent<?> event) {
		try {
			String jsonString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event);
			return jsonString;
			
		} catch(JsonProcessingException e) {
			e.printStackTrace();
		} 
		return null;
	}

	/**
	 * Returns  BigDecimal representation of the event 
	 * timestamp.
	 * 
	 * @return timestamp in BigDecimal format
	 */
	public BigDecimal getTimestamp() {
		return this.timestamp;
	}
	
	/**
	 * Returns the event's global sequence number
	 * 
	 * @return EventSequenceNumber
	 */
	public int getEventSequenceNumber() {
		return this.eventSequenceNumber;
	}
	
	/**
	 * Returns the event's name as a string.
	 * 
	 * @return EventName as a string
	 */
	public String getEventName() {
		return this.eventName;
	}
	
	
	public GhidraEventType getEventType() {
		return this.eventType;
	}
	
	/**
	 * Returns the event's source as a string.
	 * 
	 * @return EventSource as a string
	 */
	public String getEventSource() {
		return this.eventSource;
	}
	
	/**
	 * Returns the task ID, if any
	 * 
	 * @return TaskID as an int
	 */
	public int getTaskID() {
		return this.taskID;
	}
	
	/**
	 * Returns the trial ID, if any
	 * 
	 * @return TaskID as an int
	 */
	public int getTrialID() {
		return this.trialID;
	}
	
	/**
	 * Returns the task unique identifier, if any
	 * 
	 * @return TaskUUID as a string
	 */
	public String getTaskUUID() {
		return this.taskUUID;
	}
	/**
	 * Returns the program Name currently loaded
	 * 
	 * @return program name as a string
	 */
	public String getProgramName() {
		return this.programName;
	}
	
	/**
	 * Set task, trial, and UUID for this event (optional)
	 * 
	 * @param task
	 */
	public void setTaskIdentifiers(CavaTask task) {
		this.taskID=task.getTaskID();
		this.trialID=task.getTrialID();
		this.taskUUID=task.getTaskUUID();
	}
	
	/**
	 * Set task, trial, and optional taskUUID for this event 
	 * 
	 * @param taskID
	 * @param trialID
	 * @param taskUUID
	 */
	public void setTask(int taskID, int trialID, String taskUUID) {
		this.taskID=taskID;
		this.trialID=trialID;
		this.taskUUID=taskUUID;
	}
	
	/**
	 * Reset the taskID=0, trialID=0 and optional taskUUID=""
	 */
	public void resetTask() {
		this.taskID=0;
		this.trialID=0;
		this.taskUUID="";
	}
	
	/**
	 * A sequence number for all events generated upon publishing of the event. 
	 * The sequence number should be generated in a manner that 
	 * guarantees that no two distinct events ever have the same sequence number. 
	 * 
	 * @param sequenceNumber
	 */
	public void setEventSequenceNumber(int sequenceNumber) {
		this.eventSequenceNumber = sequenceNumber;
	}

	
	//----------------------------------------------------------
	//----------------------------------------------------------
	//----------------------------------------------------------
	// Factory methods for generating JSON-ready events follow
	//----------------------------------------------------------
	//----------------------------------------------------------
	//----------------------------------------------------------

	/**
	 * Generate a vertical scrollbar event
	 * 
	 * @param eventSource
	 * @param event
	 * @param eventValue
	 * @return VerticalScrollbarAdjustmentEvent
	 */
	public static VerticalScrollbarAdjustmentEvent generateVerticalScrollbarAdjustmentEvent(String eventSource, AdjustmentEvent event, int eventValue) {
		return new VerticalScrollbarAdjustmentEvent(eventSource, event, eventValue);
	}
	
	/**
	 * Generate a horizontal scrollbar event
	 * 
	 * @param eventSource
	 * @param event
	 * @param eventValue
	 * @return HorizontalScrollbarAdjustmentEvent
	 */
	public static HorizontalScrollbarAdjustmentEvent generateHorizontalScrollbarAdjustmentEvent(String eventSource, AdjustmentEvent event, int eventValue) {
		return new HorizontalScrollbarAdjustmentEvent(eventSource, event, eventValue);
	}
	
	

	
	/**
	 * Generate a mouse pressed event a
	 * 
	 * @param eventSource
	 * @param mouseEvent
	 * @return GhidraEvent<MousePressedEvent>
	 */
	public static MousePressedEvent generateMousePressedEvent(String eventSource, MouseEvent mouseEvent) {
        return new MousePressedEvent(eventSource, mouseEvent);
	}
	
	
	/**
	 * Generate a mouse clicked event 
	 * 
	 * @param eventSource
	 * @param mouseEvent
	 * @return GhidraEvent<MouseClickedEvent>
	 */
	public static MouseClickedEvent generateMouseClickedEvent(String eventSource, MouseEvent mouseEvent) {
        return new MouseClickedEvent(eventSource, mouseEvent);
	}
	
	
	/**
	 * Generate a mouse released event 
	 * 
	 * @param eventSource
	 * @param mouseEvent
	 * @return GhidraEvent<MouseReleasedEvent>
	 */
	public static MouseReleasedEvent generateMouseReleasedEvent(String eventSource, MouseEvent mouseEvent) {
        return new MouseReleasedEvent(eventSource, mouseEvent);
	}
	
	
	/**
	 * Create a mouse entered event to indicate when a mouse cursor enters a Java Swing component.
	 * 
	 * @param eventSource
	 * @param mouseEvent
	 * @return GhidraEvent<MouseEnteredEvent>
	 */
	public static MouseEnteredEvent generateMouseEnteredEvent(String eventSource, MouseEvent mouseEvent) {
        return new MouseEnteredEvent(eventSource, mouseEvent);
	}
	
	
	/**
	 * Create a mouse exited event to indicate when a mouse cursor exits a Java Swing component. 
	 * 
	 * @param eventSource
	 * @param mouseEvent
	 * @return GhidraEvent<MouseEnteredEvent>
	 */
	public static MouseExitedEvent generateMouseExitedEvent(String eventSource, MouseEvent mouseEvent) {
        return new MouseExitedEvent(eventSource, mouseEvent);
	}
	
	
	/**
	 * Create an event indicating the presence of a visual marker in a visualization tool. 
	 * 
	 * @param eventSource
	 * @param pluginEvent
	 * @param fileOffset
	 * @param pixel_x
	 * @param pixel_y
	 * @param radius
	 * @return VisualMapMarkerEvent
	 */
	public static VisualMapMarkerEvent generateVisualMapMarkerEvent(String eventSource, PluginEvent pluginEvent, long fileOffset, int pixel_x, int pixel_y, int radius) {
		return new VisualMapMarkerEvent(eventSource, pluginEvent, fileOffset, pixel_x, pixel_y, radius);
	}
	
	
	/**
	 * Create an event indicating that the instrumentation is still live and 
	 * producing event data. 
	 * 
	 * @param eventSource
	 * @return GhidraEvent<HeartbeatEvent>
	 */
	public static CavaListenerHeartbeatEvent generateHeartbeatEvent(String eventSource) {
		return new CavaListenerHeartbeatEvent(eventSource, EventTrigger.INTERNAL_ONLY);
	}
	
	
	/**
	 * Create an event indicating a ProgramLocation Ghidra intra-plugin event.
	 * 
	 * @param event
	 * @return GhidraLocationChangedEvent
	 */
	public static GhidraLocationChangedEvent generateGhidraLocationChangedEvent(ProgramLocationPluginEvent event) {
		return new GhidraLocationChangedEvent(event);
	}
	
	/**
	 * Create an event indicating a ProgramHighlight Ghidra intra-plugin event.
	 * 
	 * NOTE: Similar to selection changed events, Ghidra can have many items
	 * highlighted.  The hope is that this event only contains the most recent.
	 * 
	 * @param event
	 * @return GhidraHighlightChangedEvent
	 */
	public static GhidraHighlightChangedEvent generateGhidraHighlightChangedEvent(ProgramHighlightPluginEvent event) {
		return new GhidraHighlightChangedEvent(event);
	}
	
	/**
	 * Create an event indicating a ProgamSelection Ghidra intra-plugin event.
	 * 
	 * NOTE: Ghidra appears to allow multi-selection or split selections which makes
	 * this a bit of a mess if we really only care about the change. The backing iterator
	 * for address sets is also in address order rather than order of entry. Since
	 * we only care about the most recent change, this is problematic. 
	 * 
	 * @param selection
	 * @return GhidraSelectionChangedEvent
	 */
	public static GhidraSelectionChangedEvent generateGhidraSelectionChangedEvent(ProgramSelectionPluginEvent event) {
		return new GhidraSelectionChangedEvent(event);
	}
	
	/**
	 * Create an event indicating a ProgramActivated Ghidra intra-plugin event.
	 * 
	 * @param event
	 * @return GhidraProgramActivatedEvent
	 */
	public static GhidraProgramActivatedEvent generateGhidraProgramActivatedEvent(ProgramActivatedPluginEvent event) {		
		return new GhidraProgramActivatedEvent(event);
	}
	
	/**
	 * Create an event for Ghidra intra-plugin events that are not otherwise handled or mapped 
	 * into CAVA instrumentation events.
	 * The generated event retains only the basic info on the event details but does not extract additional features
	 * peculiar to the event.  This can be used to identify Ghidra internal events which are missed which 
	 * may indicate that additional instrumentation can be added.
	 * 
	 * @param event
	 * @return GhidraUnhandledPluginEvent
	 */
	public static GhidraUnhandledPluginEvent generateGhidraUnhandledPluginEvent(PluginEvent event) {
		return new GhidraUnhandledPluginEvent(event);
	}
	
	
	/**
	 * Create an event indicating mouse interaction with a Ghidra Listing View field. 
	 * This event occurs whenever the mouse interacts with a field.
	 * 
	 * @param eventSource
	 * @param eventName
	 * @param location
	 * @param field
	 * @param event
	 * @return FieldMouseEvent
	 */
	public static FieldMouseEvent generateFieldMouseEvent(String eventSource, FieldLocation location,
			Field field, MouseEvent event) {
		return new FieldMouseEvent(eventSource, location, field, event);
	}

	
	/**
	 * Create an event indicating a cursor interaction with a Ghidra Listing View field.
	 * This event occurs whenever the cursor position changes.
	 * 
	 * @param eventSource
	 * @param eventName
	 * @param location - The new field location
	 * @param field - The Field object containing the location
	 * @param trigger - The type of the location change 
	 * @return FieldLocationEvent
	 */
	public static FieldLocationEvent generateFieldLocationEvent(String eventSource, 
			FieldLocation location, Field field, EventTrigger trigger) {
		return new FieldLocationEvent(eventSource, location, field, trigger);
	}
	
	/**
	 * Create an event when key presses occur on a Ghidra Listing View field. 
	 * 
	 * @param eventSource
	 * @param eventName
	 * @param keyEvent - The KeyEvent generated when the user presses a key.
	 * @param index - The index of the layout the cursor was on when the key was pressed.
	 * @param fieldNum - The field index of the field the cursor was on when the key was
	 * pressed.
	 * @param row - The row in the field the cursor was on when the key was pressed.
	 * @param col - The col in the field the cursor was on when the key was pressed.
     * @param field - The current field the cursor was on when the key was pressed.
	 * @return FieldInputEvent
	 */
	public static FieldInputEvent generateFieldInputEvent(String eventSource, 
			KeyEvent keyEvent, BigInteger index, int fieldNum, int row, int col,
            Field field) {
		return new FieldInputEvent(eventSource, keyEvent, index, fieldNum, row, col, field);
	}

	/**
	 * Create an event when Ghidra Listing View fields are selected. 
	 * Occurs whenever the FieldViewer selection changes.
	 * 
	 * @param eventSource - A string name of the source of the event
	 * @param selection - The new selection
	 * @param trigger - Trigger indicating the cause of the selection change
	 * @return FieldSelectionEvent
	 */
	public static FieldSelectionEvent generateFieldSelectionEvent(String eventSource, FieldSelection selection, EventTrigger trigger) {
		return new FieldSelectionEvent(eventSource, selection, trigger);
	}
	
	/**
	 * Create an event indicating that an experimental tasks have been initialized and are ready to be shown to a subject.
	 * 
	 * @param eventSource
	 * @param event
	 * @return TaskInitializeEvent
	 */
	public static TaskInitializeEvent generateTaskInitializeEvent(String eventSource, EventTrigger event) {
		return new TaskInitializeEvent(eventSource, event);
	}
	
	/**
	 * Create an event indicating that an experimental task has been started.
	 * 
	 * @param eventSource
	 * @param event
	 * @param cavaTask
	 * @return TaskStartEvent
	 */
	public static TaskStartEvent generateTaskStartEvent(String eventSource, EventTrigger event,  CavaTask cavaTask) {
		return new TaskStartEvent(eventSource, event, cavaTask);
	}
	
	/**
	 * Create an event indicating that an experimental task has been completed.
	 * 
	 * @param eventSource
	 * @param event
	 * @param cavaTask
	 * @param result
	 * @return TaskFinishEvent
	 */
	public static TaskFinishEvent generateTaskFinishEvent(String eventSource, EventTrigger event, CavaTask cavaTask, String result) {
		return new TaskFinishEvent(eventSource, event, cavaTask, result);
	}
	
	/**
	 * Create an event indicating that an experimental task survey has been started.
	 * 
	 * @param eventSource
	 * @param event
	 * @param cavaTask
	 * @return TaskSurveyStartEvent
	 */
	public static TaskSurveyStartEvent generateTaskSurveyStartEvent(String eventSource, EventTrigger event, CavaTask cavaTask) {
		return new TaskSurveyStartEvent(eventSource, event, cavaTask);
	}
	
	/**
	 * Create an event indicating that an experimental task survey has been completed.
	 * 
	 * @param eventSource
	 * @param event
	 * @param cavaTask
	 * @param surveyResults
	 * @return TaskSurveyFinishEvent
	 */
	public static TaskSurveyFinishEvent generateTaskSurveyFinishEvent(String eventSource, EventTrigger event, CavaTask cavaTask, CavaTaskSurveyResults surveyResults) {
		return new TaskSurveyFinishEvent(eventSource, event, cavaTask, surveyResults);
	}
	
	/**
	 * Create an event indicating that the subject is being presented with the next experimental task.
	 * 
	 * @param eventSource
	 * @param event
	 * @param cavaTask
	 * @return TaskNextEvent
	 */
	public static TaskNextEvent generateTaskNextEvent(String eventSource, EventTrigger event, CavaTask cavaTask) {
		return new TaskNextEvent(eventSource, event, cavaTask);
	}
	
	/**
	 * Create an event indicating that a task is not yet complete.
	 * 
	 * @param eventSource
	 * @param event
	 * @param cavaTask
	 * @param note
	 * @return TaskIncompleteEvent
	 */
	public static TaskIncompleteEvent generateTaskIncompleteEvent(String eventSource, EventTrigger event, CavaTask cavaTask, String note) {
		return new TaskIncompleteEvent(eventSource, event, cavaTask, note);
	}
	
	/**
	 * Create an event indicating that the experiment has been completed.
	 * 
	 * @param eventSource
	 * @param event
	 * @return ExperimentCompleteEvent
	 */
	public static ExperimentCompleteEvent generateExperimentCompleteEvent(String eventSource, EventTrigger event) {
		return new ExperimentCompleteEvent(eventSource, event);
	}
	
	/**
	 * Create an event for when a mouse click is used to zoom in or out in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @param oldGraphScale
	 * @return FunctionGraphMouseClickZoomEvent
	 */
	public static FunctionGraphMouseClickZoomEvent generateFunctionGraphMouseClickZoomEvent (
			String eventSource, MouseEvent event, GraphViewer<FGVertex, FGEdge> graphViewer, Double oldGraphScale) {
		return new FunctionGraphMouseClickZoomEvent(eventSource, event, graphViewer, oldGraphScale);	
	}
	
	/**
	 * Create an event for when a mouse wheel is used to zoom in or out in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @param oldGraphScale
	 * @return FunctionGraphMouseWheelZoomEvent
	 */
	public static FunctionGraphMouseWheelZoomEvent generateFunctionGraphMouseWheelZoomEvent(String eventSource, MouseWheelEvent event, GraphViewer<FGVertex, FGEdge> graphViewer, Double oldGraphScale) {
		return new FunctionGraphMouseWheelZoomEvent(eventSource, event, graphViewer, oldGraphScale);	
	}

	/**
	 * Create an event for when a mouse hover over a graph vertex is started in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @return FunctionGraphVertexHoverEvent
	 */
	public static FunctionGraphVertexHoverEvent generateFunctionGraphVertexHoverStartEvent(String eventSource, InputEvent event, GraphViewer<FGVertex, FGEdge> graphViewer) {
		return new FunctionGraphVertexHoverEvent(eventSource, event, graphViewer, GhidraComponentMouseHoverState.HOVER_START);
	}
	
	/**
	 * Create an event for when a mouse hover over a graph edge is ended in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @return FunctionGraphVertexHoverEvent
	 */
	public static FunctionGraphVertexHoverEvent generateFunctionGraphVertexHoverEndEvent(String eventSource, InputEvent event, GraphViewer<FGVertex, FGEdge> graphViewer) {
		return new FunctionGraphVertexHoverEvent(eventSource, event, graphViewer, GhidraComponentMouseHoverState.HOVER_END);
	}
	
	/**
	 * Create an event for when a mouse hover over a graph edge is started in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @param edge
	 * @return FunctionGraphEdgeHoverEvent
	 */
	public static FunctionGraphEdgeHoverEvent generateFunctionGraphEdgeHoverStartEvent(String eventSource, InputEvent event, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge) {
		return new FunctionGraphEdgeHoverEvent(eventSource, event, graphViewer, edge, GhidraComponentMouseHoverState.HOVER_START);
	}
	
	/**
	 * Create an event for when a graph edge is hovered by the mouse in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @param edge
	 * @return FunctionGraphEdgeHoverEvent
	 */
	public static FunctionGraphEdgeHoverEvent generateFunctionGraphEdgeHoverEndEvent(String eventSource, InputEvent event, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge) {
		return new FunctionGraphEdgeHoverEvent(eventSource, event, graphViewer, edge, GhidraComponentMouseHoverState.HOVER_END);
	}
	
	/**
	 * Create an event for when a graph vertex is dragged by the mouse in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @return FunctionGraphVertexDragEvent
	 */
	public static FunctionGraphVertexDragEvent generateFunctionGraphVertexDragEvent(String eventSource, MouseEvent event, GraphViewer<FGVertex, FGEdge> graphViewer) {
		return new FunctionGraphVertexDragEvent(eventSource, event, graphViewer);
	}
	
	/**
	 * Create an event for when a graph vertex is clicked by the mouse in the GraphViewer.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @return FunctionGraphVertexClickEvent
	 */
	public static FunctionGraphVertexClickEvent generateFunctionGraphVertexClickEvent(String eventSource, MouseEvent event, GraphViewer<FGVertex, FGEdge> graphViewer) {
		return new FunctionGraphVertexClickEvent(eventSource, event, graphViewer);
	}
	
	/**
	 * Create an event for when a graph edge is picked.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @param edge
	 * @return FunctionGraphEdgePickEvent
	 */
	public static FunctionGraphEdgePickEvent generateFunctionGraphEdgePickedEvent(String eventSource, MouseEvent event, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge) {
		return new FunctionGraphEdgePickEvent(eventSource, event, graphViewer, edge, FunctionGraphEdgePickedState.PICKED);
	}
	
	/**
	 * Create an event for when a graph edge is unpicked.
	 * 
	 * @param eventSource
	 * @param event
	 * @param graphViewer
	 * @param edge
	 * @return FunctionGraphEdgePickEvent
	 */
	public static FunctionGraphEdgePickEvent generateFunctionGraphEdgeUnPickedEvent(String eventSource, MouseEvent event, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge) {
		return new FunctionGraphEdgePickEvent(eventSource, event, graphViewer, edge, FunctionGraphEdgePickedState.UNPICKED);
	}
	/**
	 * Create an event for when the code attempts to find the distance between two addresses. 
	 * 
	 * @param clickedAddress
	 * @param keyAddress
	 * @param assemblyDistance
	 * @param blockDistance
	 * @param functionDistance
	 * @param taskID
	 * @param descriptor
	 * @param pluginEvent
	 * @param taskDescription
	 * @return GraphDistanceEvent
	 */
	public static GraphDistanceEvent generateGraphDistanceEvent (
			String clickedAddress, String keyAddress, int assemblyDistance, int blockDistance, int functionDistance, String taskID, String descriptor, ProgramLocationPluginEvent pluginEvent, String taskDescription) {
		return new GraphDistanceEvent(clickedAddress, keyAddress, assemblyDistance, blockDistance, functionDistance, taskID, descriptor, pluginEvent, taskDescription);	
	}
}




/**
 * Enumeration of Ghidra Event Types
 * 
 * @author Sunny J. Fugate
 */
enum GhidraEventType {
	GHIDRA_SELECTION_CHANGED_EVENT ("GhidraSelectionChangedEvent"),
	GHIDRA_HIGHLIGHT_CHANGED_EVENT ("GhidraHighlightChangedEvent"),
	GHIDRA_LOCATION_CHANGED_EVENT ("GhidraLocationChangedEvent"),
	GHIDRA_UNHANDLED_PLUGIN_EVENT ("GhidraUnhandledPluginEvent"),
	GHIDRA_PROGRAM_ACTIVATED_EVENT ("GhidraProgramActivatedEvent"),
	VERTICAL_SCROLLBAR_ADJUSTMENT_EVENT ("VerticalScrollbarAdjustmentEvent"),
	HORIZONTAL_SCROLLBAR_ADJUSTMENT_EVENT ("HorizontalScrollbarAdjustmentEvent"),
	CAVA_LISTENER_HEARTBEAT_EVENT ("CavaListenerHeartbeat"),
	UNHANDLED_INTERACTION_EVENT ("UnhandledInteractionEvent"),
	MOUSE_PRESSED_EVENT ("MousePressedEvent"),
	MOUSE_CLICKED_EVENT ("MouseClickedEvent"),
	MOUSE_RELEASED_EVENT ("MouseReleasedEvent"),
	MOUSE_ENTERED_EVENT ("MouseEnteredEvent"),
	MOUSE_EXITED_EVENT ("MouseExitedEvent"),
	KEYBOARD_INTERACTION_EVENT ("KeyboardInteractionEvent"),
	VISUAL_MAP_MARKER_EVENT ("VisualMapMarkerEvent"),
	FIELD_MOUSE_EVENT ("FieldMouseEvent"),
	FIELD_INPUT_EVENT ("FieldInputEvent"),
	FIELD_LOCATION_EVENT ("FieldLocationEvent"),
	FIELD_SELECTION_EVENT ("FieldSelectionEvent"),
	TASK_SEQUENCE_EVENT ("TaskSequenceEvent"),
	TASK_INITIALIZE_EVENT ("TaskSequenceInitializationEvent"),
	TASK_START_EVENT ("TaskStartEvent"),
	TASK_FINISH_EVENT ("TaskFinishEvent"),
	TASK_INCOMPLETE_EVENT ("TaskIncompleteEvent"),
	TASK_SURVEY_START_EVENT ("TaskSurveyStartEvent"),
	TASK_SURVEY_FINISH_EVENT ("TaskSurveyFinishEvent"),
	TASK_NEXT_EVENT ("TaskNextEvent"),
	EXPERIMENT_COMPLETE_EVENT ("ExperimentCompleteEvent"),
	FUNCTION_GRAPH_VERTEX_EVENT ("FunctionGraphVertexEvent"), //Abstract type
	FUNCTION_GRAPH_EDGE_EVENT ("FunctionGraphEdgeEvent"), //Abstract type
	FUNCTION_GRAPH_ZOOM_EVENT ("FunctionGraphZoomEvent"), //Abstract type
	FUNCTION_GRAPH_MOUSE_CLICK_ZOOM_EVENT ("FunctionGraphMouseClickZoomEvent"), 
	FUNCTION_GRAPH_MOUSE_WHEEL_ZOOM_EVENT ("FunctionGraphMouseWheelZoomEvent"), 
	FUNCTION_GRAPH_VERTEX_HOVER_EVENT ("FunctionGraphVertexHoverEvent"), 
	FUNCTION_GRAPH_EDGE_HOVER_EVENT ("FunctionGraphEdgeHoverEvent"),
	FUNCTION_GRAPH_VERTEX_DRAG_EVENT ("FunctionGraphVertexDragEvent"),
	FUNCTION_GRAPH_VERTEX_CLICK_EVENT ("FunctionGraphVertexClickEvent"),
	FUNCTION_GRAPH_EDGE_PICK_EVENT ("FunctionGraphEdgePickEvent"),
	GRAPH_DISTANCE_EVENT("GraphDistanceEvent"),
	;

	public final String eventName; 
	
	private GhidraEventType(String name) {
		this.eventName = name;
	}
	
	public String getName() {
		return this.eventName;
	}
}

/**
 * Enumeration of mouse hover states for use in related event types
 * @author Sunny J. Fugate
 */
enum GhidraComponentMouseHoverState {
	HOVER_START,
	HOVER_ACTIVE,
	HOVER_END
}

/**
 * Enumeration of graph edge picked states
 * @author Sunny J. Fugate
 */
enum FunctionGraphEdgePickedState {
	PICKED,
	UNPICKED,
}

/**
 * Event class to indicate when an experimental task is initialized.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskInitializeEvent")
class TaskInitializeEvent extends GhidraEvent<TaskInitializeEvent> {
	public TaskInitializeEvent(String eventSource, EventTrigger event) {
		super(GhidraEventType.TASK_INITIALIZE_EVENT, eventSource, event);
	}
}

/**
 * Event class to indicate when an experimental task is started.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskStartEvent")
class TaskStartEvent extends GhidraEvent<TaskStartEvent> {
	@JsonProperty("TaskName")				public String taskName;
	@JsonProperty("TaskSequenceNumber")		public int taskSequenceNumber;
	@JsonProperty("TaskStartingAddress")	public String taskStartingAddress;
	@JsonProperty("TaskEndingAddress")		public String taskEndingAddress;
	@JsonProperty("TaskProgram")			public String taskProgram;
	@JsonProperty("TaskAnswerKey")			public String taskAnswerKey;
	@JsonProperty("TaskKeyAddresses")		public String[][] taskKeyAddresses;
	@JsonProperty("TaskExpectedResponse")	public String taskExpectedResponse;
	@JsonProperty("TaskInstructions")		public String taskInstructions;

	public TaskStartEvent(String eventSource, EventTrigger event, CavaTask task) {
		super(GhidraEventType.TASK_START_EVENT, eventSource, event);
		
		//The task information as loaded into Ghidra
		taskSequenceNumber = task.getSequence();
		taskName = task.getName();
		taskInstructions = task.getInstructions();
		taskStartingAddress = task.getStart();
		taskEndingAddress = task.getEnd();
		taskProgram = task.getProgram();
		taskAnswerKey = task.getAnswerKey();
		taskKeyAddresses = task.getKeyAddresses();
		taskExpectedResponse = task.getExpectedResponse();
		
		setTaskIdentifiers(task);
	}
}

/**
 * Event class to indicate when an experimental task is completed.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskFinishEvent")
class TaskFinishEvent extends GhidraEvent<TaskFinishEvent> {
	@JsonProperty("TaskName")				public String taskName;
	@JsonProperty("TaskSequenceNumber")		public int taskSequenceNumber;
	@JsonProperty("TaskStartingAddress")	public String taskStartingAddress;
	@JsonProperty("TaskEndingAddress")		public String taskEndingAddress;
	@JsonProperty("TaskProgram")			public String taskProgram;
	@JsonProperty("TaskAnswerKey")			public String taskAnswerKey;
	@JsonProperty("TaskKeyAddresses")		public String[][] taskKeyAddresses;
	@JsonProperty("TaskExpectedResponse")	public String taskExpectedResponse;
	@JsonProperty("TaskResultResponse")		public String taskResultResponse;
	@JsonProperty("TaskInstructions")		public String taskInstructions;

	public TaskFinishEvent(String eventSource, EventTrigger event, CavaTask task, String result) {
		super(GhidraEventType.TASK_FINISH_EVENT, eventSource, event);
		
		//The task information as loaded into Ghidra
		taskSequenceNumber = task.getSequence();
		taskName = task.getName();
		taskInstructions = task.getInstructions();
		taskStartingAddress = task.getStart();
		taskEndingAddress = task.getEnd();
		taskProgram = task.getProgram();
		taskAnswerKey = task.getAnswerKey();
		taskKeyAddresses = task.getKeyAddresses();
		taskExpectedResponse = task.getExpectedResponse();

		//Input from the user
		taskResultResponse = result;
		
		setTaskIdentifiers(task);
	}
}

/**
 * Event class to indicate when an experimental intra-task survey is started.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskSurveyStartEvent")
class TaskSurveyStartEvent extends GhidraEvent<TaskSurveyStartEvent> {
	@JsonProperty("TaskSequenceNumber")		public int taskSequenceNumber;
	@JsonProperty("TaskName")				public String taskName;
	@JsonProperty("SurveyTasks")			public String surveyTasks;
	
	public TaskSurveyStartEvent(String eventSource, EventTrigger event, CavaTask task) {
		super(GhidraEventType.TASK_SURVEY_START_EVENT, eventSource, event);
		taskName = task.getName();
		taskSequenceNumber = task.getSequence();
		surveyTasks = task.getSurveytasks();
		
		setTaskIdentifiers(task);
	}
}

/**
 * Event class to indicate when an experimental intra-task survey is completed.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskSurveyFinishEvent")
class TaskSurveyFinishEvent extends GhidraEvent<TaskSurveyFinishEvent> {
	@JsonProperty("Question1")				public String question1;
	@JsonProperty("Scale1")					public String scale1;
	@JsonProperty("Response1")				public String response1;
	@JsonProperty("Comment1")				public String comment1;
	
	@JsonProperty("Question2")				public String question2;
	@JsonProperty("Scale2")					public String scale2;
	@JsonProperty("Response2")				public String response2;
	@JsonProperty("Comment2")				public String comment2;
	
	@JsonProperty("Question3")				public String question3;
	@JsonProperty("Response3")				public String response3;
	@JsonProperty("Scale3")					public String scale3;
	@JsonProperty("Comment3")				public String comment3;
	
	@JsonProperty("TaskSequenceNumber")		public int taskSequenceNumber;
	@JsonProperty("TaskName")				public String taskName;
	@JsonProperty("SurveyTasks")			public String surveyTasks;
	
	public TaskSurveyFinishEvent(String eventSource, EventTrigger event, CavaTask task, CavaTaskSurveyResults surveyResults) {
		super(GhidraEventType.TASK_SURVEY_FINISH_EVENT, eventSource, event);
		
		taskName = task.getName();
		taskSequenceNumber = task.getSequence();
		surveyTasks = task.getSurveytasks();
		
		question1=surveyResults.question1;
		question2=surveyResults.question2;
		question3=surveyResults.question3;
		
		response1=surveyResults.response1;
		response2=surveyResults.response2;
		response3=surveyResults.response3;
		
		scale1=surveyResults.scale1;
		scale2=surveyResults.scale2;
		scale3=surveyResults.scale3;
		
		comment1=surveyResults.comment1;
		comment2=surveyResults.comment2;
		comment3=surveyResults.comment3;
		
		setTaskIdentifiers(task);
	}
}

/**
 * Event class to indicate when the next task is loaded. 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskNextEvent")
class TaskNextEvent extends GhidraEvent<TaskNextEvent> {
	@JsonProperty("TaskSequenceNumber")		public int taskSequenceNumber;
	@JsonProperty("TaskName")				public String taskName;
	
	public TaskNextEvent(String eventSource, EventTrigger event, CavaTask task) {
		super(GhidraEventType.TASK_NEXT_EVENT, eventSource, event);
		taskName = task.getName();
		taskSequenceNumber = task.getSequence();
		
		setTaskIdentifiers(task);
	}
}

/**
 * Event class to indicate that a task is incomplete.  This may be triggered if a subject attempts
 * to complete a task but has not entered a required field.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "TaskIncompleteEvent")
class TaskIncompleteEvent extends GhidraEvent<TaskIncompleteEvent> {
	@JsonProperty("Note")	public String note;
	@JsonProperty("TaskSequenceNumber")		public int taskSequenceNumber;
	@JsonProperty("TaskName")				public String taskName;
	
	public TaskIncompleteEvent(String eventSource, EventTrigger event, CavaTask task, String note) {
		super(GhidraEventType.TASK_INCOMPLETE_EVENT, eventSource, event);
		taskName = task.getName();
		taskSequenceNumber = task.getSequence();
		
		setTaskIdentifiers(task);
		this.note=note;
	}
}

/**
 * Event class to indicate when a task sequence is completed and the experiment is finished.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "ExperimentCompleteEvent")
class ExperimentCompleteEvent extends GhidraEvent<ExperimentCompleteEvent> {
	public ExperimentCompleteEvent(String eventSource, EventTrigger event) {
		super(GhidraEventType.EXPERIMENT_COMPLETE_EVENT, eventSource, event);
	}
}


/**
 * Event class to indicate that a marker shown on a visual map was updated (used in the Cantordust plugin).
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "VisualMapMarkerEvent")
class VisualMapMarkerEvent extends GhidraEvent<VisualMapMarkerEvent> {
	@JsonProperty("AddressOffset") 	public long addressOffset;
	@JsonProperty("X") 				public int x; //X-coord from left of the JComponent
	@JsonProperty("Y") 				public int y; //Y-coord from top of the JComponent 
	@JsonProperty("Radius") 		public int radius;
	
	public VisualMapMarkerEvent(String eventSource, PluginEvent event, long fileOffset, int x, int y, int radius) {
		super(GhidraEventType.VISUAL_MAP_MARKER_EVENT, eventSource, event);
		
		this.addressOffset=fileOffset;
		this.x=x;
		this.y=y;
		this.radius=radius;
	}
}

/**
 * Base class for keyboard interactions where keys are pressed and released.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "KeyboardInteractionEvent")
class KeyboardInteractionEvent extends GhidraEvent<KeyboardInteractionEvent> {
	@JsonProperty("KeyCode") 		public int keyCode;
	@JsonProperty("KeyChar") 		public char keyChar;
	@JsonProperty("AltDown") 		public boolean altDown;
	@JsonProperty("ShiftDown") 		public boolean shiftDown;
	@JsonProperty("MetaDown") 		public boolean metaDown;
	@JsonProperty("CtrlDown")		public boolean ctrlDown;
	@JsonProperty("Modifiers")		public int modifiers;
	@JsonProperty("ModifiersText")	public String modifiersText;
	
	public KeyboardInteractionEvent(String eventSource, KeyEvent keyEvent) {
		super(GhidraEventType.KEYBOARD_INTERACTION_EVENT, eventSource, keyEvent);
		
		keyCode = keyEvent.getKeyCode();
		keyChar = keyEvent.getKeyChar();
		altDown = keyEvent.isAltDown();
		metaDown = keyEvent.isMetaDown();
		ctrlDown = keyEvent.isControlDown();
		shiftDown = keyEvent.isShiftDown();
		modifiers = keyEvent.getModifiersEx();
		modifiersText = InputEvent.getModifiersExText(modifiers);
	}
}

/**
 * Base class for mouse interaction events
 * @author Sunny J. Fugate
 */
abstract class MouseInteractionEvent<T> extends GhidraEvent<T> {

	@JsonProperty("MouseButton") 		public int mouseButton;
	@JsonProperty("ClickCount") 		public int clickCount;
	@JsonProperty("RelativeX") 			public int relativeX;
	@JsonProperty("RelativeY") 			public int relativeY;
	 @JsonProperty("AbsoluteX") 		public int absoluteX;
	 @JsonProperty("AbsoluteY") 		public int absoluteY;
	 @JsonProperty("Button1Down") 		public boolean button1Down;
	 @JsonProperty("Button2Down") 		public boolean button2Down;
	 @JsonProperty("Button3Down") 		public boolean button3Down;
	 @JsonProperty("CtrlDown") 			public boolean ctrlDown;
	 @JsonProperty("AltDown") 			public boolean altDown;
	 @JsonProperty("ShiftDown") 		public boolean shiftDown;
	 @JsonProperty("MetaDown") 			public boolean metaDown;
	 @JsonProperty("IsPopupTrigger") 	public boolean isPopupTrigger;
	 @JsonProperty("Modifiers") 		public int modifiers;
	 @JsonProperty("ModifiersText") 	public String modifiersText;
	
	
	public MouseInteractionEvent(GhidraEventType eventType, String eventSource, MouseEvent mouseEvent) {
		super(eventType, eventSource, mouseEvent);
		
		this.modifiers=mouseEvent.getModifiersEx();
		this.modifiersText=MouseEvent.getMouseModifiersText(this.modifiers);
		
		this.mouseButton=mouseEvent.getButton();
		this.clickCount=mouseEvent.getClickCount();
		this.relativeX=mouseEvent.getX();
		this.relativeY=mouseEvent.getY();
		this.absoluteX=mouseEvent.getXOnScreen();
		this.absoluteY=mouseEvent.getYOnScreen();
		this.button1Down=(this.modifiers & InputEvent.BUTTON1_DOWN_MASK) != 0;
		this.button2Down=(this.modifiers & InputEvent.BUTTON2_DOWN_MASK) != 0;
		this.button3Down=(this.modifiers & InputEvent.BUTTON3_DOWN_MASK) != 0;
		this.altDown=(this.modifiers & InputEvent.ALT_DOWN_MASK) != 0;
		this.ctrlDown=(this.modifiers & InputEvent.CTRL_DOWN_MASK) != 0;
		this.metaDown=(this.modifiers & InputEvent.META_DOWN_MASK) != 0;
		this.shiftDown=(this.modifiers & InputEvent.SHIFT_DOWN_MASK) != 0;
		this.isPopupTrigger=mouseEvent.isPopupTrigger();	
	}
}

/**
 * Event class to indicate when a mouse button is pressed.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "MousePressedEvent")
class MousePressedEvent extends MouseInteractionEvent<MousePressedEvent> {
	public MousePressedEvent(String eventSource, MouseEvent mouseEvent) {
		super(GhidraEventType.MOUSE_PRESSED_EVENT, eventSource, mouseEvent);
	}
}

/**
 * Event class to indicate when a mouse button is clicked (pressed then released).
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "MouseClickedEvent")
class MouseClickedEvent extends MouseInteractionEvent<MouseClickedEvent> {
	public MouseClickedEvent(String eventSource, MouseEvent mouseEvent) {
		super(GhidraEventType.MOUSE_CLICKED_EVENT, eventSource, mouseEvent);
	}
}

/**
 * Event class to indicate when a mouse button is released.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "MouseReleasedEvent")
class MouseReleasedEvent extends MouseInteractionEvent<MouseReleasedEvent> {
	public MouseReleasedEvent(String eventSource, MouseEvent mouseEvent) {
		super(GhidraEventType.MOUSE_RELEASED_EVENT, eventSource, mouseEvent);
	}
}

/**
 * Event class to indicate when a mouse cursor enters an instrumented Java Swing component. 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "MouseEnteredEvent")
class MouseEnteredEvent extends MouseInteractionEvent<MouseEnteredEvent> {
	public MouseEnteredEvent(String eventSource, MouseEvent mouseEvent) {
		super(GhidraEventType.MOUSE_ENTERED_EVENT, eventSource, mouseEvent);
	}
}

/**
 * Event class to indicate when a mouse cursor exits an instrumented Java Swing component.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "MouseExitedEvent")
class MouseExitedEvent extends MouseInteractionEvent<MouseExitedEvent> {
	public MouseExitedEvent(String eventSource, MouseEvent mouseEvent) {
		super(GhidraEventType.MOUSE_EXITED_EVENT, eventSource, mouseEvent);
	}
}

/**
 * Event class to indicate when a vertical scrollbar is adjusted through direct or indirect interaction.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "VerticalScrollbarAdjustmentEvent")
class VerticalScrollbarAdjustmentEvent extends GhidraEvent<VerticalScrollbarAdjustmentEvent> {
	@JsonProperty("ScrollbarLocation") public long scrollbarLocation;

	public VerticalScrollbarAdjustmentEvent(String eventSource, AdjustmentEvent event, int adjustmentValue) {
		super(GhidraEventType.VERTICAL_SCROLLBAR_ADJUSTMENT_EVENT, eventSource, event);
		this.scrollbarLocation=adjustmentValue;
	}
}

/**
 * Event class to indicate when a horizontal scrollbar is adjusted through  direct or indirect interaction.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "HorizontalScrollbarAdjustmentEvent")
class HorizontalScrollbarAdjustmentEvent extends GhidraEvent<HorizontalScrollbarAdjustmentEvent> {
	@JsonProperty("ScrollbarLocation") public long scrollbarLocation;

	public HorizontalScrollbarAdjustmentEvent(String eventSource, AdjustmentEvent event, int adjustmentValue) {
		super(GhidraEventType.HORIZONTAL_SCROLLBAR_ADJUSTMENT_EVENT, eventSource, event);
		this.scrollbarLocation=adjustmentValue;
	}
}

/**
 * Event class used to indicate that instrumentation is live even when other events are not
 * being produced due to lack of user interactions. 
 * 
 * @author Jon Buch
 */
@JsonRootName(value = "CavaListenerHeartbeatEvent")
class CavaListenerHeartbeatEvent extends GhidraEvent<CavaListenerHeartbeatEvent> {
	public CavaListenerHeartbeatEvent(String eventSource, EventTrigger eventTrigger) {
		super(GhidraEventType.CAVA_LISTENER_HEARTBEAT_EVENT, eventSource, eventTrigger);
	}
}

/**
 * Event class to indicate when a program is activated in Ghidra.
 * 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "GhidraProgramActivatedEvent")
class GhidraProgramActivatedEvent extends GhidraEvent<GhidraProgramActivatedEvent> {
	
	@JsonProperty("IsNullProgram") public boolean isNullProgram=true;
	
	public GhidraProgramActivatedEvent(ProgramActivatedPluginEvent pluginEvent) {
		super(GhidraEventType.GHIDRA_PROGRAM_ACTIVATED_EVENT, pluginEvent);
		
		//If the active program is null, store it as the current global
		if(pluginEvent.getActiveProgram() == null) { 
			return; 
		}
		
		isNullProgram = false;
	}
}

/**
 * Event class indicating when Ghidra's location is changed/updated.
 * 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "GhidraLocationChangedEvent")
class GhidraLocationChangedEvent extends GhidraEvent<GhidraLocationChangedEvent> {	
	@JsonProperty("ByteAddress") 	public String byteAddress=null; 
	@JsonProperty("Row") 			public Integer row=null;
	@JsonProperty("Column") 		public Integer column=null;
	@JsonProperty("CharOffset") 	public Integer charOffset=null;
	@JsonProperty("IsNullLocation") public boolean isNullLocation=true;
	
	public GhidraLocationChangedEvent(ProgramLocationPluginEvent pluginEvent) {
		super(GhidraEventType.GHIDRA_LOCATION_CHANGED_EVENT,pluginEvent);
		
		//If location is null, return an empty object
		if(pluginEvent.getLocation() == null) { return; }
		
		this.isNullLocation=false;
		ProgramLocation location=pluginEvent.getLocation();
		this.byteAddress = location.getByteAddress().toString();
		
		this.row = location.getRow();
		this.column = location.getColumn();
		this.charOffset = location.getCharOffset();
	}
	
	@Override
	public String toString() {
		return getEventType()+"[ Source: "+getEventSource()+", Address: "+byteAddress+", Row: "+ row+", column: "+ column+", charOffset: "+charOffset+ " ]";
	}
}

/**
 * Event class to indicate the distance of the subject's current location and key locations (such as the locations of 
 * a known defect, salient distractor, or beacon. When the user is performing RE clicks on a new address and is doing a POI or POV 
 * task distances are calculated and events generated for each key address provided for the task. 
 * The distances can be set to -1 if we fail to find the path between two addresses in different functions
 * or we do find the path but they are not logically connected. To help distinguish these two cases I added a 
 * "descriptor" field which is set to "NOT FOUND" when the function distance is too great and "NOT CONNECTED"
 * when the path is found but logically the two addresses do not connect.
 * 
 * @author Jeremy P. Johnson
 */
@JsonRootName(value = "GraphDistanceEvent")
class GraphDistanceEvent extends GhidraEvent<GraphDistanceEvent> {
	@JsonProperty("ClickedAddress") 		public String clickedAddress;
	@JsonProperty("KeyAddress") 		public String keyAddress;
	@JsonProperty("AssemblyDistance") 		public int assemblyDistance;
	@JsonProperty("BlockDistance") 		public int blockDistance;
	@JsonProperty("FunctionDistance") 		public int functionDistance;
	@JsonProperty("taskID")			public String taskID;
	//descriptor can be: "FOUND" || "NOT FOUND" || "NOT CONNECTED"
	//	- The difference between not found and not connected, the first means the distance was too great and the latter means we found them but logically they don't connect.
	@JsonProperty("Descriptor")			public String descriptor;
	@JsonProperty("TaskDescription")			public String taskDescription;

	public GraphDistanceEvent(String clickedAddress, String keyAddress, int assemblyDistance, int blockDistance, int functionDistance, String taskID, String descriptor, ProgramLocationPluginEvent pluginEvent, String taskDescription) {
		//Using the same super() as ProgramLocationChangedEvent, both utilize the pluginEvent!
		super(GhidraEventType.GRAPH_DISTANCE_EVENT, pluginEvent);
		this.clickedAddress = clickedAddress;
		this.keyAddress = keyAddress;
		this.assemblyDistance = assemblyDistance;
		this.blockDistance = blockDistance;
		this.functionDistance = functionDistance;
		this.descriptor = descriptor;
		this.taskID = taskID;
		this.taskDescription = taskDescription;
	}
	@Override
	public String toString() {
		String output = getEventType()+"[ Source: "+getEventSource()+", clickedAddress: "+ clickedAddress +", keyAddress: "+ keyAddress;
		output = output + " | Assembly Distance: " + assemblyDistance + " | Block Distance: " + blockDistance + " | Function Distance: " + functionDistance + " | Descriptor: " + descriptor + " | Task Description: " + taskDescription + " ]";
		return output;
	}
}



/**
 * Event class for changes to the selection of content in the Ghidra Listing View. 
 * This event indicates that the mouse or keyboard has been
 * used to select a portion of the content of a view.  Key features
 * include the min address, max address of the selection. 
 * 
 * The number of selections may be greater than one. 
 * 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "GhidraSelectionChangedEvent")
class GhidraSelectionChangedEvent extends GhidraEvent<GhidraSelectionChangedEvent> {
	@JsonProperty("MinSelectionAddress") 		public String minSelectionAddress=null;
	@JsonProperty("MaxSelectionAddress") 		public String maxSelectionAddress=null;
	@JsonProperty("NumberOfSelectionRanges") 	public Integer numberOfSelectionRanges=0;
	@JsonProperty("IsNullSelection")			public boolean isNullSelection=true;
	
	public GhidraSelectionChangedEvent(ProgramSelectionPluginEvent pluginEvent) {
		super(GhidraEventType.GHIDRA_SELECTION_CHANGED_EVENT, pluginEvent); //sets event observed timestamp
		
		ProgramSelection selection = pluginEvent.getSelection();

		//Return an empty object if selection is null or empty
		if(selection == null) { return; }
		if(selection.isEmpty()) { return; }
		
		this.isNullSelection=false;
		
		this.numberOfSelectionRanges = selection.getNumAddressRanges();
		this.minSelectionAddress = selection.getMinAddress().toString();
		this.maxSelectionAddress = selection.getMaxAddress().toString();
	}
	
	@Override
	public String toString() {
		return getEventType()+"[ MinSelectionAddress:"+minSelectionAddress+", MaxSelectionAddress:"+ maxSelectionAddress+", NumberOfSelectionRanges:"+ numberOfSelectionRanges+" ]";
	}
}


/**
 * Event class for changes to the highlighting in the Ghidra Listing View.  
 * In the Ghidra tool, highlight events create persistent annotation in the listing or decompile views. 
 * 
 * @author Sunny J. Fugate
 *
 */
@JsonRootName(value = "GhidraHighlightChangedEvent")
class GhidraHighlightChangedEvent extends GhidraEvent<GhidraHighlightChangedEvent> {
	@JsonProperty("MinHighlightAddress") 		public String minHighlightAddress = null;
	@JsonProperty("MaxHighlightAddress") 		public String maxHighlightAddress = null;
	@JsonProperty("NumberOfHighlightRanges") 	public Integer numberOfHighlightRanges = 0;
	@JsonProperty("isNullHighlight")			public boolean isNullHighlight = true;
	
	public GhidraHighlightChangedEvent(ProgramHighlightPluginEvent pluginEvent) {
		super(GhidraEventType.GHIDRA_HIGHLIGHT_CHANGED_EVENT, pluginEvent); 
		
		ProgramSelection selection = pluginEvent.getHighlight();
		
		//If selection is null or empty, then this is a null highlight
		if(selection == null) { return; }
		if(selection.isEmpty()) { return; } 
		
		isNullHighlight=false;
		
		this.numberOfHighlightRanges = selection.getNumAddressRanges();
		this.minHighlightAddress = selection.getMinAddress().toString();
		this.maxHighlightAddress = selection.getMaxAddress().toString();
	}
	
	@Override
	public String toString() {
		return getEventType()+"[ MinHighlightAddress:" +minHighlightAddress+", MaxHighlightAddress:"+maxHighlightAddress+", NumberOfHighlightRanges:"+numberOfHighlightRanges+"]";
	}
}

/**
 * Event class for all Ghidra intra-plugin events which are not yet explicitly handled as CAVA events
 * 
 * @author Sunny J. Fugate
 *
 */
@JsonRootName(value = "GhidraUnhandledPluginEvent")
class GhidraUnhandledPluginEvent extends GhidraEvent<GhidraUnhandledPluginEvent> {
	public GhidraUnhandledPluginEvent(PluginEvent pluginEvent) {
		super(GhidraEventType.GHIDRA_UNHANDLED_PLUGIN_EVENT, pluginEvent);
	}
}

/**
 * Event class for selection of Ghidra Listing View fields.
 * 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FieldSelectionEvent")
class FieldSelectionEvent extends GhidraEvent<FieldSelectionEvent> {
	@JsonProperty("NumRanges") 				Integer numRanges=0;
	@JsonProperty("FieldRanges") 			String[] fieldRanges=null;
	@JsonProperty("IsNullFieldSelection") 	boolean isNullFieldSelection=true;
	
	public FieldSelectionEvent(String eventSource, FieldSelection selection, EventTrigger trigger) {
		super(GhidraEventType.FIELD_SELECTION_EVENT, eventSource, trigger);
		numRanges = selection.getNumRanges();
		
		if(numRanges == 0) { return; }
		
		this.isNullFieldSelection=false;
		
		//Create an array of ranges in string form start:end 
		fieldRanges = new String[numRanges];
		for(int i=0;i<numRanges;i++) {
			FieldRange r = selection.getFieldRange(i);
			fieldRanges[i]=r.getStart()+":"+r.getEnd();
		}		
	}
}

/**
 * Event class for mouse interactions with Ghidra Listing View fields. 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FieldMouseEvent")
class FieldMouseEvent extends MouseInteractionEvent<FieldMouseEvent> { 
	@JsonProperty("FieldText") 		public String fieldText;
	@JsonProperty("FieldColumn") 	public int column;
	@JsonProperty("FieldRow") 		public int row;
	@JsonProperty("FieldX") 		public int x;
	@JsonProperty("FieldY") 		public int y;
	@JsonProperty("FieldWidth") 	public int width;
	@JsonProperty("FieldHeight") 	public int height;
	@JsonProperty("FieldNum") 		public int fieldNum;
	@JsonProperty("FieldIndex") 	public BigInteger index;
	@JsonProperty("FieldHashCode") 	public int fieldHashCode;
	
	public FieldMouseEvent(String eventSource, FieldLocation location, Field field, MouseEvent mouseEvent) {
		super(GhidraEventType.FIELD_MOUSE_EVENT, eventSource, mouseEvent);
		this.overrideEventType(GhidraEventType.FIELD_MOUSE_EVENT); //Update event type
		
		fieldText = field.getText();
		
		column = location.getCol();
		row = location.getRow();
		x = field.getX(row, column);
		y = field.getY(row);
		
		height = field.getHeight();
		width = field.getWidth();
		
		fieldNum = location.getFieldNum();
		index = location.getIndex();
		
		fieldHashCode = field.hashCode();
		
	}
}

/**
 * Event class for cursor location events relating to a Ghidra Listing View field.
 * 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FieldLocationEvent")
class FieldLocationEvent extends GhidraEvent<FieldLocationEvent> {
	@JsonProperty("FieldText") 			public String fieldText;
	@JsonProperty("FieldColumn") 		public int column; 
	@JsonProperty("FieldRow") 			public int row;
	@JsonProperty("FieldX") 			public int x;
	@JsonProperty("FieldY") 			public int y;
	@JsonProperty("FieldWidth") 		public int width;
	@JsonProperty("FieldHeight") 		public int height; 
	@JsonProperty("FieldNum") 			public int fieldNum;
	@JsonProperty("FieldIndex") 		public BigInteger index; 
	@JsonProperty("FieldHashCode") 		public int fieldHashCode;
	@JsonProperty("EventTriggerType") 	public String eventTriggerType;
	
	public FieldLocationEvent(String eventSource, FieldLocation location, Field field, EventTrigger trigger) {
		super(GhidraEventType.FIELD_LOCATION_EVENT, eventSource, trigger);
				
		fieldText = field.getText();
		
		column = location.getCol();
		row = location.getRow();
		x = field.getX(row, column);
		y = field.getY(row);
		
		height = field.getHeight();
		width = field.getWidth();
		
		fieldNum = location.getFieldNum();
		index = location.getIndex();
		
		fieldHashCode = field.hashCode();

		eventTriggerType = trigger.toString();
	}
}

/**
 * Event class for input to a Ghidra Listing View field. 
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FieldInputEvent")
class FieldInputEvent extends KeyboardInteractionEvent {
	@JsonProperty("FieldText")		public String fieldText;
	@JsonProperty("FieldColumn")	public int fieldColumn;
	@JsonProperty("FieldRow")		public int fieldRow;
	@JsonProperty("FieldNum")		public int fieldNum;
	@JsonProperty("FieldIndex")		public BigInteger fieldIndex;
	@JsonProperty("FieldHashCode")	public int fieldHashCode;
	
	public FieldInputEvent(String eventSource, KeyEvent keyEvent, BigInteger index, int _fieldNum, int row, int col, Field field) {
		super(eventSource, keyEvent);
		
		this.overrideEventType(GhidraEventType.FIELD_INPUT_EVENT);
		
		fieldText = field.getText();
		
		fieldColumn = col;
		fieldRow = row;
		
		fieldNum = _fieldNum;
		fieldIndex = index;
		
		fieldHashCode = field.hashCode();
	}
}



/**
 * Base class for function graph vertex interactions. 
 */
abstract class FunctionGraphVertexEvent extends GhidraEvent<FunctionGraphVertexEvent> {
	@JsonProperty("VertexAddress")						public String vertexAddress=null;
	@JsonProperty("VertexTitle")						public String vertexTitle=null;
	@JsonProperty("VertexIsSelected")					public Boolean vertexIsSelected=null;
	@JsonProperty("VertexMinAddress")					public String vertexMinAddress=null;
	@JsonProperty("VertexMaxAddress")					public String vertexMaxAddress=null;
	@JsonProperty("InputEventType")						public String inputEventType=null;
	@JsonProperty("IsScaledPastInteractionThreshold")	public Boolean isScaledPastInteractionThreshold=null;
	@JsonProperty("ViewLocationX")						public Double viewLocationX=null;
	@JsonProperty("ViewLocationY")						public Double viewLocationY=null;
	
	public FunctionGraphVertexEvent(String eventSource, GraphViewer<FGVertex, FGEdge> graphViewer, InputEvent inputEvent) {
		super(GhidraEventType.FUNCTION_GRAPH_VERTEX_EVENT, eventSource, inputEvent);
		
		this.isScaledPastInteractionThreshold = GraphViewerUtils.isScaledPastVertexInteractionThreshold(graphViewer);

		//Use VertexMouseInfo to determine picked elements
		if(inputEvent instanceof MouseEvent) {
			VertexMouseInfo<FGVertex, FGEdge> vertexMouseInfo = GraphViewerUtils.convertMouseEventToVertexMouseEvent(graphViewer, (MouseEvent)inputEvent);
			if(vertexMouseInfo == null) { return; }
			
			FGVertex vertex = vertexMouseInfo.getVertex();
			if(vertex == null) { return; }
			
			this.vertexIsSelected = vertexMouseInfo.isVertexSelected();
			this.vertexTitle = vertex.getTitle();
			
			AddressSetView addressSet = vertex.getAddresses();
			if(!addressSet.isEmpty()) {
				this.vertexMinAddress = addressSet.getMinAddress().toString();
				this.vertexMaxAddress = addressSet.getMaxAddress().toString();
			}
			
			Address _vertexAddress = vertex.getVertexAddress();
			if(_vertexAddress != null) {
				this.vertexAddress = _vertexAddress.toString();
			}
			
			
			this.viewLocationX = vertex.getLocation().getX();
			this.viewLocationY = vertex.getLocation().getY();
			
			//System.out.println(vertexMouseInfo.toString());
			
		}
	}
}

/**
 * Event class for mouse hover events over graph vertexes.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphVertexHoverEvent")
class FunctionGraphVertexHoverEvent extends FunctionGraphVertexEvent {
	@JsonProperty("MouseHoverState")		public GhidraComponentMouseHoverState mouseHoverState;
	public FunctionGraphVertexHoverEvent(String eventSource, InputEvent inputEvent, GraphViewer<FGVertex, FGEdge> graphViewer, GhidraComponentMouseHoverState mouseHoverState) {
		super(eventSource, graphViewer, inputEvent);
		
		this.mouseHoverState=mouseHoverState;
	}
}

/**
 * Event class for mouse hover events over graph edges.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphEdgeHoverEvent")
class FunctionGraphEdgeHoverEvent extends FunctionGraphEdgeEvent {
	@JsonProperty("MouseHoverState")		public GhidraComponentMouseHoverState mouseHoverState;
	public FunctionGraphEdgeHoverEvent(String eventSource, InputEvent inputEvent, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge, GhidraComponentMouseHoverState mouseHoverState) {
		super(eventSource, inputEvent, graphViewer, edge);
		
		this.mouseHoverState=mouseHoverState;
	}
}

/**
 * Abstract event class for Function graph zoom events.
 * 
 * Note: There should be no JsonRootName decorator as this is an abstract class.
 * @author Sunny J. Fugate
 */
abstract class FunctionGraphZoomEvent extends GhidraEvent<FunctionGraphZoomEvent> {
	@JsonProperty("GraphScale")							public Double graphScale=null;
	@JsonProperty("PreviousGraphScale")					public Double previousGraphScale=null;
	@JsonProperty("InputEventType")						public String inputEventType=null;

	public FunctionGraphZoomEvent(String eventSource, InputEvent inputEvent, GraphViewer<FGVertex, FGEdge> graphViewer, Double previousGraphScale) {
		super(GhidraEventType.FUNCTION_GRAPH_ZOOM_EVENT, eventSource, inputEvent);
		
		this.graphScale = GraphViewerUtils.getGraphScale(graphViewer);
		this.previousGraphScale = previousGraphScale;		
	}
}

/**
 * Abstract event class for Function Graph mouse zoom events
 * 
 * Note: There should be no JsonRootName decorator as this is an abstract class.
 * @author Sunny J. Fugate
 */
abstract class FunctionGraphMouseZoomEvent extends FunctionGraphZoomEvent {
	@JsonProperty("RelativeX") 		public int relativeX;
	@JsonProperty("RelativeY") 		public int relativeY;
	@JsonProperty("AbsoluteX") 		public int absoluteX;
	@JsonProperty("AbsoluteY") 		public int absoluteY;
	 
	public FunctionGraphMouseZoomEvent(String eventSource, MouseEvent mouseEvent,
			GraphViewer<FGVertex, FGEdge> graphViewer, Double previousGraphScale) {
		super(eventSource, mouseEvent, graphViewer, previousGraphScale);
		
		this.relativeX=mouseEvent.getX();
		this.relativeY=mouseEvent.getY();
		this.absoluteX=mouseEvent.getXOnScreen();
		this.absoluteY=mouseEvent.getYOnScreen();
	}
}

/**
 * Event class for mouse zoom events initiated via a click on Function Graph components.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphMouseClickZoomEvent")
class FunctionGraphMouseClickZoomEvent extends FunctionGraphMouseZoomEvent {
public FunctionGraphMouseClickZoomEvent(String eventSource, MouseEvent mouseEvent,
			GraphViewer<FGVertex, FGEdge> graphViewer, Double previousGraphScale) {
		super(eventSource, mouseEvent, graphViewer, previousGraphScale);

	}
}

/**
 * Event class for mouse zoom events initiated via a mouse wheel on a Function Graph.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphMouseWheelZoomEvent")
class FunctionGraphMouseWheelZoomEvent extends FunctionGraphMouseZoomEvent {
	@JsonProperty("PreciseWheelRotation")	public double preciseWheelRotation;
public FunctionGraphMouseWheelZoomEvent(String eventSource, MouseWheelEvent mouseWheelEvent,
			GraphViewer<FGVertex, FGEdge> graphViewer, Double previousGraphScale) {
		super(eventSource, mouseWheelEvent, graphViewer, previousGraphScale);
		
		this.preciseWheelRotation = mouseWheelEvent.getPreciseWheelRotation();
	}
}

/**
 * Event class for mouse drag events over Function Graph vertexes.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphVertexDragEvent")
class FunctionGraphVertexDragEvent extends FunctionGraphVertexEvent {
	@JsonProperty("RelativeX") 		public int relativeX;
	@JsonProperty("RelativeY") 		public int relativeY;
	@JsonProperty("AbsoluteX") 		public int absoluteX;
	@JsonProperty("AbsoluteY") 		public int absoluteY;
	
	public FunctionGraphVertexDragEvent(String eventSource, MouseEvent mouseEvent, GraphViewer<FGVertex, FGEdge> graphViewer) {
		super(eventSource, graphViewer, mouseEvent);
		
		this.relativeX=mouseEvent.getX();
		this.relativeY=mouseEvent.getY();
		this.absoluteX=mouseEvent.getXOnScreen();
		this.absoluteY=mouseEvent.getYOnScreen();
	}
}


/**
 * Event class for mouse click events on Function Graph vertexes.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphVertexClickEvent")
class FunctionGraphVertexClickEvent extends FunctionGraphVertexEvent {
	@JsonProperty("MouseClickCount")	public Integer mouseClickCount = null;
	@JsonProperty("RelativeX") 			public int relativeX;
	@JsonProperty("RelativeY") 			public int relativeY;
	@JsonProperty("AbsoluteX") 			public int absoluteX;
	@JsonProperty("AbsoluteY") 			public int absoluteY;
	
	public FunctionGraphVertexClickEvent(String eventSource, MouseEvent mouseEvent, GraphViewer<FGVertex, FGEdge> graphViewer) {
		super(eventSource, graphViewer, mouseEvent);

		this.mouseClickCount = mouseEvent.getClickCount();
		
		this.relativeX=mouseEvent.getX();
		this.relativeY=mouseEvent.getY();
		this.absoluteX=mouseEvent.getXOnScreen();
		this.absoluteY=mouseEvent.getYOnScreen();
	}
}


/**
 * Base class for Function Graph edge manipulation events
 * @author vagrant
 *
 */
abstract class FunctionGraphEdgeEvent extends GhidraEvent<FunctionGraphEdgeEvent> {
	@JsonProperty("StartingAddress")					public String startingAddress = null;
	@JsonProperty("EndingAddress")						public String endingAddress = null;	
	@JsonProperty("InputEventType")						public String inputEventType;
	@JsonProperty("IsScaledPastInteractionThreshold")	public Boolean isScaledPastInteractionThreshold=null;

	public FunctionGraphEdgeEvent(String eventSource, InputEvent inputEvent, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge) {
		super(GhidraEventType.FUNCTION_GRAPH_EDGE_EVENT, eventSource, inputEvent);
		
		this.isScaledPastInteractionThreshold = GraphViewerUtils.isScaledPastVertexInteractionThreshold(graphViewer);
		
		FGVertex startVertex = edge.getStart();
		FGVertex endVertex = edge.getEnd();
		
		if(startVertex != null) {
			Address address =startVertex.getVertexAddress();
			if(address != null) {
				this.startingAddress = address.toString();
			}
		}
		if(endVertex != null) {
			Address address = endVertex.getVertexAddress();
			if(address != null) {
				this.endingAddress = address.toString();
			}
		}
	}
}


/**
 * Event class for pick events on Function Graph edges.
 * @author Sunny J. Fugate
 */
@JsonRootName(value = "FunctionGraphEdgePickEvent")
class FunctionGraphEdgePickEvent extends FunctionGraphEdgeEvent {
	@JsonProperty("EdgePickedState")	public FunctionGraphEdgePickedState edgePickedState = null;
	@JsonProperty("RelativeX") 			public int relativeX;
	@JsonProperty("RelativeY") 			public int relativeY;
	@JsonProperty("AbsoluteX") 			public int absoluteX;
	@JsonProperty("AbsoluteY") 			public int absoluteY;
	
	public FunctionGraphEdgePickEvent(String eventSource, MouseEvent mouseEvent, GraphViewer<FGVertex, FGEdge> graphViewer, FGEdge edge, FunctionGraphEdgePickedState edgePickedState) {
		super(eventSource, mouseEvent, graphViewer, edge);
		
		this.edgePickedState = edgePickedState;
		
		this.relativeX=mouseEvent.getX();
		this.relativeY=mouseEvent.getY();
		this.absoluteX=mouseEvent.getXOnScreen();
		this.absoluteY=mouseEvent.getYOnScreen();
	}
}