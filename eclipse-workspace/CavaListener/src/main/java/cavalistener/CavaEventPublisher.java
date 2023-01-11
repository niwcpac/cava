package cavalistener;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.LinkedBlockingQueue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;


/**
* Class to encompass data formatting, encapsulation, socket management, and 
* transmission to a suitably configured 'sink'.  Maintains one or more persistent
* network sockets for transmission of instrumentation data. 
* 
* Currently abstracts network connections as "StreamingLayers" to accommodate
* the LabStreamingLayer protocol. 
* 
* StreamingLayers:
* 	- stdout : StdOutStreamingLayer
*   - file : LogFileStreamingLayer 
*   - tcp : TcpStreamingLayer 
*   - udp : UdpStreamingLayer
*   - lsl : LabStreamingLayer -- fails due to JNA issues with Ghidra plugin loading
* 
* @author Sunny Fugate, Naval Information Warfare Center, Pacific
*
*/
public class CavaEventPublisher implements Runnable {
	//Jackson JSON object mapper
	private static ObjectMapper mapper = new ObjectMapper();
	private static int sequenceNumber = 0;
	
	private static int taskID=0;
	private static int trialID=0;
	private static String taskUUID="";
	
	//Store a list of streaming layers to enable multiple simultaneous streams to be sent
	private ArrayList<StreamingLayer> dataStreamingLayers = new ArrayList<StreamingLayer>();
	//TODO: possibly use a dictionary if we want to limit number of each streaming layer
	
	private HashMap<StreamingLayer,Thread> streamingLayerThreads = new HashMap<StreamingLayer,Thread>();
	
	
	//TODO: move this to GhidraOptions
	//private static String lslChannel="ghidra101";

	
	private static LinkedBlockingQueue<GhidraEvent<?>> eventQueue=null;
	
	/**
	 * Default constructor for use by event generators/instrumentation plugins
	 * 
	 */
	public CavaEventPublisher() {
		
	}
	
	/**
	 * Constructor with a specified LinkedBlockingQueue to ingest
	 * GhidraEvent objects. 
	 * 
	 * @param queue
	 */
	public CavaEventPublisher(LinkedBlockingQueue<GhidraEvent<?>> queue) {
		eventQueue=queue;
		
		//Directives for Jackson JSON to include root object name in JSON
		mapper.enable(DeserializationFeature.UNWRAP_ROOT_VALUE); 
		mapper.enable(SerializationFeature.WRAP_ROOT_VALUE);
		
		//Attempt to start the cava system service
		startCavaSystemService();
	}
	
	/**
	 * Kicks off the CAVA event forwarding service
	 * which translates UDP event packets to the LabStreamingLayer.
	 * This is hardcoded to try and run our startup script. 
	 * 
	 * @return true if process returns status 0
	 */
	public boolean startCavaSystemService() {
		//Run system command to kick off Cava forwarding service
	    //TODO: make this configurable
		String command = "/home/vagrant/startCavaDaemons.sh";
		Process process;
		try {
			process = Runtime.getRuntime().exec(command);
			process.waitFor(); //Wait for process to return;
			
			if(process.exitValue()==0) {
				System.out.println("Cava Event Forwarding Service Started: "+command);
				process.destroy();
				return true;
			} 
			process.destroy();
		} catch (IOException e) {
			System.out.println("Error starting Cava Event Forwarding Service");
			e.printStackTrace();
			
		} catch (InterruptedException e) {
			System.out.println("Attempt to start Cava Event Forwarding Service was interrupted");
			e.printStackTrace();
		}
		System.out.println("Start service manually using: "+command);
		
		return false;
	}
	
	/**
	 * Return the global event queue
	 * @return
	 */
	public static LinkedBlockingQueue<GhidraEvent<?>> getEventQueue() {
		return eventQueue;
	}
	
	/**
	 * Add a new StreamingLayer for events to be published to
	 * 
	 * @param streamingLayer
	 */
	public void addDataStreamer(StreamingLayer streamingLayer) {
		Thread streamingThread = new Thread(streamingLayer);
		
		System.out.println("Adding data streamer:"+streamingLayer.getStreamingLayerInfo());
		
		streamingLayerThreads.put(streamingLayer, streamingThread);
		dataStreamingLayers.add(streamingLayer);
		
		System.out.println("Data streaming layer count:"+dataStreamingLayers.size());
		
		System.out.println("Starting data streamer:"+streamingLayer.getStreamingLayerInfo());
		streamingThread.start();
	}	
	
	
	@Override
	public void run() {
		while(true) {
			//Wait for the next item
			try {
				//Blocking wait for next event on queue
				GhidraEvent<?> event = eventQueue.take();
				
				//If there are not streaming layer threads, continue to wait, events are dropped
				if(streamingLayerThreads.isEmpty()) { continue; }
				
				transmitNewEvent(event);
			} catch (InterruptedException e) {
				// Output error, but continue if possible
				e.printStackTrace();
			}
		}
		
	}
	

	
	/**
	 * Close and dispose of all data streaming threads
	 */
	public void removeAllDataStreamers() {
		System.out.println("Removing data streaming layers.");
		
		Iterator<StreamingLayer> iterator = dataStreamingLayers.iterator();
		
		while(iterator.hasNext()) {
			StreamingLayer streamingLayer = iterator.next();
		
			System.out.println(dataStreamingLayers.size()+" streaming layers to remove.");

			//First remove the streaming layer from the list
			iterator.remove();
			
			//Then stop the streaming layer thread
			streamingLayer.stop();
			
			//Then destroy and dispose of the streaming layer
			System.out.println("Removing streaming layer: "+streamingLayer.getStreamingLayerInfo());
			streamingLayer.destroy();
			
			//For good measure, set the reference to the streaming layer to null
			streamingLayer = null;
		}
	}
	
	/**
	 * Take a dequeued event and send it using a data streamer or stdout.
	 * 
	 * This method may be useful to be called from elsewhere
	 * for performing event injection outside of the event queue.
	 */
	private void transmitNewEvent(GhidraEvent<?> event) {
		String data=null;
		
		sequenceNumber=sequenceNumber + 1;
		event.setEventSequenceNumber(sequenceNumber);
		
		//If not a start or finish event, set the task details
		if(!(event instanceof TaskStartEvent) && !(event instanceof TaskFinishEvent)) {
			event.setTask(taskID, trialID, taskUUID);
		}
		
		try {
			data = mapper.writeValueAsString(event);		
		} catch(JsonProcessingException e) {
			//TODO: better error handling
			System.out.println(e.getMessage());
			return;
		}
		
		if(data==null) {
			//TODO: possibly throw exception?
			System.out.println("Processed null event for publishing, skipping");
			return;
		}
		
		if(dataStreamingLayers.size() == 0) { //Default to stdout?
			//TODO: throw exception instead?
			System.out.println("CavaEventPublisher: No data streaming layers configured for sending events"); 
			System.out.println(data);
			return;
		}
		
		
		/*
		 * For each StreamingLayer, send the event data
		 */
		for(StreamingLayer dataStreamer : dataStreamingLayers) {
			//Cleanup data streaming threads which are no longer valid
			if(!dataStreamer.isValid()) { 
				Thread thread = this.streamingLayerThreads.remove(dataStreamer);
				if(thread!=null) { thread.interrupt(); }
				thread=null;
				continue;
			}
			
			try {
				dataStreamer.sendData(data);
			} catch (StreamingLayerException e) {
				System.out.println("StreamingLayerException: "+e.getMessage());
				//e.printStackTrace();
			}
		}
		
		
		//If a task start or task finish event, set the task info
		//which will be emitted for future events.
		if(event instanceof TaskStartEvent) {
			//Set the task details for all events
			taskID=event.getTaskID();
			trialID=event.getTrialID();
			taskUUID=event.getTaskUUID();

		} else if(event instanceof TaskSurveyFinishEvent || event instanceof TaskNextEvent) {
			//Reset the task details for all events
			taskID=0;
			trialID=0;
			taskUUID="";
		}
		
	}

	/**
	 * Returns the global sequence number
	 * @return
	 */
	public int getSequenceNumber() {
		return sequenceNumber;
	}
	
	/**
	 * If the queue is instantiated, 
	 * send event to the global event publishing queue.
	 * 
	 * @param ghidraEvent
	 */
	public static void publishNewEvent(GhidraEvent<?> ghidraEvent) {
		if(eventQueue == null) {
			//Attempt to obtain the queue
			eventQueue=CavaEventPublisher.getEventQueue();
		}
		
		if(eventQueue != null) {
			eventQueue.add(ghidraEvent);
		} else {
			System.out.println("Event queue is not yet created.  Start the CavaListenerPlugin to begin publishing events.");
		}
	}

}
