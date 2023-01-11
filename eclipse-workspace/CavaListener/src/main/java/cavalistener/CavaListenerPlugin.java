/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cavalistener;

import java.net.UnknownHostException;
import java.util.TimerTask;
import java.util.concurrent.LinkedBlockingQueue;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Listens for Ghidra events and various UI events.",
	description = "Used for instrumentation of Ghidra user interface for purposes of human subject experimentation.", 
	servicesRequired = { ProgramManager.class, GoToService.class }
)
//@formatter:on
/**
 * This is the core plugin class for running the CAVA instrumentation framework. This plugin
 * provides at minimum: access to a global static queue used for each instrumented plugin for purposes of 
 * instrumentation event publishing; a means of publishing events to a file or network socket; 
 * a graphical interface for interacting with subjects or guiding them through tasks; and 
 * possibly a graphical interface for managing or configuring the instrumentation framework. 
 * 
 * @author Sunny J. Fugate
 */
public class CavaListenerPlugin extends ProgramPlugin {
    
	CavaEventDisplayProvider provider;
	LinkedBlockingQueue<GhidraEvent<?>> eventQueue=new LinkedBlockingQueue<GhidraEvent<?>>();
	LinkedBlockingQueue<PluginEvent> pluginEventQueue=new LinkedBlockingQueue<PluginEvent>();

	CavaEventPublisher eventPublisher=new CavaEventPublisher(eventQueue);
	CavaPerformanceMetrics performanceMetrics = new CavaPerformanceMetrics(pluginEventQueue);  
	Thread eventPublisherThread;
	Thread performanceMetricsThread;
	Thread eventHeartbeatThread;
	
	ProgramManager programManagerService; 
	
	// Amount of time between HeartbeatEvents in milliseconds
	static final public int HEARTBEATDELAY = 10000; //TODO: change back to 1000?
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CavaListenerPlugin(PluginTool tool) {
		super(tool);
		
		eventPublisherThread = new Thread(eventPublisher);
		performanceMetricsThread = new Thread(performanceMetrics);
		eventHeartbeatThread = new Thread(new CavaHeartbeat());
		
		String pluginName = getName();
		provider = new CavaEventDisplayProvider(this, tool, pluginName); 
	}

	/**
	 * Resets the current location to the specified address for the program.
	 * Address should be a hexadecimal string such as 00100000
	 */
	protected void goToSpecifiedAddress(String hexAddress) {
		Address startAddress = this.getCurrentProgram().getAddressFactory().getAddress(hexAddress);
		this.goTo(startAddress);
	}
	
	/**
	 * Sets the active program based on provided program name.  
	 * If there is no match, this should have no effect.
	 */
	protected void setActiveProgram(String name) {
		programManagerService = tool.getService(ProgramManager.class);
		Program[] programs = programManagerService.getAllOpenPrograms();
		for (Program p : programs) {
			if (p.getName().equals(name)) {
				programManagerService.setCurrentProgram(p);
				break;
			}
		}
		
	}
	/**
	 * Resets the current location to the minimum address for the program.
	 */
	protected void goToStartingAddress() {
		if(currentProgram == null) { 
			System.out.println("Cannot change location, no program");
			return;
		}
		
		this.goTo(currentProgram.getMinAddress());
	}

	@Override
	public void dispose() {		
		//Cleanup data streamers, releasing any resources and freeing bound TCP/USP sockets
		
		System.out.println("Shutting down CavaListenerPlugin");
		eventPublisher.removeAllDataStreamers();
	
		//Call superclass dispose
		super.dispose();
	}
	
	@Override
	public void init() {
		super.init();

		eventPublisherThread.start();
		performanceMetricsThread.start();
		
		
		StreamingLayer stdoutDataStreamer = new StdOutStreamingLayer(); 
		eventPublisher.addDataStreamer(stdoutDataStreamer);
		
		StreamingLayer fileDataStreamer = new FileStreamingLayer("/opt/cava-log/ghidra.log");
		eventPublisher.addDataStreamer(fileDataStreamer);
		
		// Note: We initially attempted but were unable to  get LSL working directly with Ghidra without a segmentation fault.
		// We believe this is due to the use of native libraries in both LSL and Ghidra. 
		// The Ghidra documentation makes it clear that native libraries should not be used. 
		/*
		StreamingLayer lslDataStreamer = new LabStreamingLayer("ghidra101");
		eventPublisher.addDataStreamer(lslDataStreamer);
		*/
		
		try {
			StreamingLayer datagramStreamer = new DatagramStreamingLayer("127.0.0.1", 1111, 2001);
			eventPublisher.addDataStreamer(datagramStreamer);
		} catch (UnknownHostException e) {
			System.out.println("Error creating DatagramStreamingLayer");
			e.printStackTrace();
		}

		//Send single heartbeat on startup
		sendHeartbeat(CavaListenerPlugin.class.getSimpleName());
		
		eventHeartbeatThread.start();
	}
	
	/**
	 * CavaHeartbeat Class, similar to the function sendHeartbeat(), 
	 * this class is used for sending Heartbeat events at consistent intervals
	 * TODO: Determine if another method for keeping the timing is necessary
	 * 
	 * @author Jonathan Buch
	 *
	 */
	class CavaHeartbeat extends TimerTask {
		@Override
		public void run() {
			while(true) {
				// TODO Auto-generated method stub
				try {
					Thread.sleep(HEARTBEATDELAY);
					
					GhidraEvent<?> ghidraEvent = GhidraEvent.generateHeartbeatEvent(CavaListenerPlugin.class.getSimpleName());
					sendGhidraEventUpdate(ghidraEvent);
				
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	/**
	 * Sends a single heartbeat with a source and a name
	 * 
	 * @param eventSource a string name of the source such as "MyGhidraPlugin"
	 * @param eventName a descriptive name for the event like "MyGhidraPlugin Heartbeat"
	 * 
	 * @author Jonathan Buch
	 */
	public void sendHeartbeat(String eventSource) {
		GhidraEvent<?> ghidraEvent = GhidraEvent.generateHeartbeatEvent(CavaListenerPlugin.class.getSimpleName());
		sendGhidraEventUpdate(ghidraEvent);
	}
	
	/**
	 * Return the total count of events transmitted
	 * @return the event count
	 */
	public int getEventCount() {
		return this.eventPublisher.getSequenceNumber();
	}
	
	/**
	 * Process an standard Ghidra intra-plugin event. 
	 * This is the method used to capture the location change
	 * and other core/common Ghidra events produced by Ghidra
	 * plugins. 
	 */
	@Override
	public void processEvent(PluginEvent pluginEvent) {
		super.processEvent(pluginEvent);

		GhidraEvent<?> ghidraEvent = null;
		
		if(pluginEvent instanceof ProgramLocationPluginEvent) {
			this.pluginEventQueue.add(pluginEvent);
			ghidraEvent=GhidraEvent.generateGhidraLocationChangedEvent((ProgramLocationPluginEvent) pluginEvent);
		} else if(pluginEvent instanceof ProgramHighlightPluginEvent) {
			ghidraEvent=GhidraEvent.generateGhidraHighlightChangedEvent((ProgramHighlightPluginEvent) pluginEvent);
		} else if(pluginEvent instanceof ProgramSelectionPluginEvent) {
			ghidraEvent=GhidraEvent.generateGhidraSelectionChangedEvent((ProgramSelectionPluginEvent) pluginEvent);
		} else if(pluginEvent instanceof ProgramActivatedPluginEvent) {
			ghidraEvent=GhidraEvent.generateGhidraProgramActivatedEvent((ProgramActivatedPluginEvent) pluginEvent);
		} else {
			ghidraEvent=GhidraEvent.generateGhidraUnhandledPluginEvent(pluginEvent);
		}	
		
		provider.processEvent(ghidraEvent);
		sendGhidraEventUpdate(ghidraEvent);
	}
	
	/**
	 * Forwards events to one or more remote subscribers
	 * @param GhidraEvent to forward
	 */
	public void sendGhidraEventUpdate(GhidraEvent<?> event) {
		if(event==null) {
			System.out.println("Warning: null event received by CAVA Listener, ignoring");
			return;
		}
		
		//Add the event to the output queue
		this.eventQueue.add(event);
	}
}
