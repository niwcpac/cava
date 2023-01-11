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
package cavafunctiongraph;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.*;

import cavalistener.CavaEventListener;
import cavalistener.CavaEventPublisher;
import cavalistener.CavaUtils;
import cavalistener.GhidraEvent;
import edu.uci.ics.jung.visualization.control.GraphMouseListener;
import edu.uci.ics.jung.visualization.picking.PickedState;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ViewChangedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.functiongraph.FGProvider;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertexListingPanel;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.graph.viewer.SatelliteGraphViewer;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = PluginCategoryNames.GRAPH,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = CavaFunctionGraphPlugin.FUNCTION_GRAPH_NAME,
	description = "Plugin to show a graphical representation of the code blocks of a function, basic extension of the FunctionGraphPlugin.",
	servicesRequired = { GoToService.class, BlockModelService.class, CodeViewerService.class, ProgramManager.class },
	eventsConsumed = { ProgramLocationPluginEvent.class, ViewChangedPluginEvent.class }
)
//@formatter:on

/**
 * This plugin is a small extension to the standard Function Graph plugin in which interactions
 * with the graph are instrumented for purposes of human subjects experimentation. 
 * 
 * The goal of this extension is to provide sufficient instrumentation of the plugin to provide insights 
 * into how a subject interacts with the function graph.  Many features are not yet instrumented. 
 * 
 * Events which may be relevant to watch: 
 *  Zoom : Mouse : scroll
 *  Zoom : Keyboard : Ctrl + =/-
 *  Zoom : Mouse : Double click Block/Block Header
 *  Context Menu : Mouse : Right Click
 *  Pan : Mouse : click and drag
 *  Pan : Keyboard (arrows)?
 *  Pan : Scrollbar??
 *  Pan : Mouse : click in satellite view
 *  Selection : Mouse : click on vertex
 *  Selection : Mouse : click on edge
 *  Move Block : Mouse : click and drag block header
 *  Highlight : Mouse : click and draft within block
 *  Show References : Keyboard : Ctrl + Shift + F
 *  Create Label : Keyboard : L
 *  
 * @author Sunny J. Fugate
 */
public class CavaFunctionGraphPlugin extends FunctionGraphPlugin {
	//Attempt to hide the parent class plugin name? Doesn't work due to use of superclass fields
	static final String FUNCTION_GRAPH_NAME = "Cava Function Graph";
	static final String PLUGIN_OPTIONS_NAME = FUNCTION_GRAPH_NAME;
	
	private double graphScale;
	
	String cavaComponentName = "CavaFunctionGraphPlugin";

	FGProvider provider;
	
	//Store a reference to each Function Graph that has been instrumented, not working, using a single flag instead
	//TODO: this may mean that the graph instances (or at least the swing objects are torn down when not in use)
	static final HashSet<VisualGraph<FGVertex, FGEdge>> instrumentedVisualGraphs = new HashSet<VisualGraph<FGVertex, FGEdge>>();
	Timer instrumentationTask=null;
	int instrumentationAttempts=0;
	
	GraphViewer<FGVertex, FGEdge> lastInstrumentedGraphViewer=null;
	
	FGVertex lastHoveredVertex=null;
	HashSet<FGEdge> currentPickedEdges=new HashSet<FGEdge>();
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CavaFunctionGraphPlugin(PluginTool tool) {
		super(tool);

	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	/**
	 * Add instrumentation for each visible provider on program location changes. 
	 * 
	 * The FunctionGraph can change on every program location change, so attempt re-instrumentation on each:
	 * - ProgramLocationPluginEvent - for when the program changes location (e.g. navigations in the CodeBrowser) 
     * - ViewChangedPluginEvent - to update the listeners when the Code Browser is showing (e.g. Navigation of Graph elements which trigger Code Browser location updates)
	 */
	@Override 
	public void processEvent(PluginEvent pluginEvent) {
		super.processEvent(pluginEvent);
	
		if(pluginEvent instanceof ProgramLocationPluginEvent || pluginEvent instanceof ViewChangedPluginEvent ) {
			System.out.println("FunctionGraphPlugin: Attempting Instrumentation of the FunctionGraphPlugin");
			addCavaEventListeners();
		} 
	}
	/**
	 * Creates a TimerTask and calls addCavaEventListeners at the specified delayed time. 
	 * 
	 * This instrumentation thread continues indefinitely to capture edge cases where the display updates but 
	 * where no associated ProgramLocationPluginEvent occurs. 
	 * 
	 * TODO: determine the nature of edge cases and simplify the instrumentation
	 * 
	 * @param connectedProvider 	the provider to instrument
	 * @param delay	milliseconds 	to delay new instrumentation attempt
	 * @param attempts				the number of attempts to make for a single provider after an attempted component instrumentation
	 */
	private void createDelayedInstrumentationTask(int delay) {
		if(instrumentationTask != null && instrumentationTask.isRunning()) { return; } //Don't add more tasks, we have one running
		
		instrumentationAttempts=instrumentationAttempts+1;
		
		//Action listener used for delayed instrumentation, for use if instrumentation fails due to delays in Swing/AWT component creation
		ActionListener actionListener=new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				addCavaEventListeners();
			}
		};
				
		Timer task = new Timer(delay, actionListener);
		task.setRepeats(false);
		task.start();
		instrumentationTask=task;
	}
	
	/**
	 * Adds event listeners for this CAVA component and its provider(s). 
	 * 
	 * This call should be idempotent and multiple calls should result in the same behavior. 
	 * However, whether a component is already instrumented should *not* be handled here, 
	 * but at the component level.  This is currently handled within the CavaEventListener class 
	 * by storing a HashMap indicating which specific components have been instrumented.  In this 
	 * way if a particular JComponent is not ready it may be re-instrumented on a later attempt. 
	 * 
	 */
	private boolean addCavaEventListeners() {
		boolean satelliteStatus = false;
		boolean primaryStatus = false;
		
		//Catch instances where the tool is not constructed or is being torn down
		if(tool==null) { return false; }
		
		//Obtain the tool's active component provider list
		List<FGProvider> providers = tool.getWindowManager().getComponentProviders(FGProvider.class);
		//TODO: fix race condition where new provider isn't available yet and old provider is still visible
		
		//System.out.println("FunctionGraphPlugin: provider count = "+providers.size());
		
		//For each visible provider, add instrumentation
		for(FGProvider theProvider : providers) { //Search for the visible provider
			//System.out.println("FunctionGraphPlugin: Checking FGProvider from connected provider list: "+theProvider.hashCode());
			
			//Obtain the top level component for the provider
			//All other components will hang off of this one, somewhere
			VisualGraphView<FGVertex, FGEdge, FunctionGraph> visualGraphView = theProvider.getView();
						
			GraphViewer<FGVertex, FGEdge> graphViewer = visualGraphView.getPrimaryGraphViewer();
			
			VisualGraph<FGVertex, FGEdge> visualGraph = visualGraphView.getVisualGraph();
			
			//Skip any viewers which are null
			if(graphViewer == null) { 
				System.out.println("GraphViewer is null, skipping instrumentation");
				continue; 
			}
			
			//System.out.println("FunctionGraphPlugin: Adding CAVA listeners to FGProvider.VisualGraphView: " + graphViewer.hashCode());
			
			//Note: re-loading a previously instrumented graph results in no events... they must be re-instrumented each time they are created

			if(this.lastInstrumentedGraphViewer == graphViewer) {
				System.out.println("Skipping GraphViewer instrumentation as we *just* instrumented this viewer");
				continue;
			}
			
			//Instrument the SatelliteGraphViewer	
			satelliteStatus = addSatelliteGraphViewerListeners(visualGraphView);

			//Instrument a new provider
			primaryStatus = addGraphViewerListeners(visualGraphView); 
			
			System.out.println("FunctionGraphPlugin: FGProvider.VisualGraphView: " + graphViewer.hashCode() + " have been instantiated");		
			if(primaryStatus) { 
				instrumentedVisualGraphs.add(visualGraph);  //This does not work properly
				//Trying this instead:
				this.lastInstrumentedGraphViewer = graphViewer; 
				//This should result in re-instrumentation each time a graph viewer is loaded *after* switching to a different GraphViewer
			}
			
			//TODO: make use of satelliteStatus
		}
		
		//System.out.println("FunctionGraphPlugin: GraphViewer/SatelliteViewer are not ready");
		
		/* NOTE: currently cannot capture all instances where the Function graph is redrawn, so just keep trying.... */
		createDelayedInstrumentationTask(1000);	
		return primaryStatus;
	}
	
	/**
	 * TODO: implement me
	 * @param visualGraphView
	 * @return
	 */
	private boolean addSatelliteGraphViewerListeners(VisualGraphView<FGVertex, FGEdge, FunctionGraph> visualGraphView) {
		SatelliteGraphViewer<FGVertex, FGEdge> satelliteViewer = visualGraphView.getSatelliteViewer();
		
		String componentName=cavaComponentName+"_SatelliteGraphViewer";
		//Bail if the satellite view is null (disabled?)
		if(satelliteViewer == null) { return false;	} 
		
		//Add listeners for mouse interaction events
		CavaEventListener.instrumentMouseInteraction(componentName, satelliteViewer);
		
		satelliteViewer.addMouseWheelListener(new MouseWheelListener() {

			@Override
			public void mouseWheelMoved(MouseWheelEvent event) {
				checkGraphScaleChanged(visualGraphView.getPrimaryGraphViewer(), componentName, event);
			}
		});
		return true;
	}
	
	/**
	 * Add all of the detailed instrumentation required for the FGProvider
	 * 
	 * @param connectedProvider
	 */
	private boolean addGraphViewerListeners(VisualGraphView<FGVertex, FGEdge, FunctionGraph> visualGraphView) {
		boolean instrumentationStatus = false;
		GraphViewer<FGVertex, FGEdge> graphViewer = visualGraphView.getPrimaryGraphViewer();
		
		//Instrument mouse interactions with the primary GraphViewer panel
		CavaEventListener.instrumentMouseInteraction(cavaComponentName, graphViewer);
		CavaEventListener.instrumentMouseWheel(cavaComponentName, graphViewer);
		//Far too verbose and probably not necessary: CavaEventListener.instrumentMouseMotion(cavaComponentName, graphViewer);
		
		//Add listeners for mouse interaction with the graph
		addGraphMouseListeners(graphViewer); //Listeners for interactions with graph vertices
		addMouseListeners(graphViewer); //Other mouse interactions with the graph view (e.g. edge picks, whitespace clicks, etc)
		addMouseMotionListeners(visualGraphView); //Events triggered by mouse movement such as hover events
		addMouseWheelListener(graphViewer); //Events triggered by mouse wheel such as zoom events
		
		VisualGraph<FGVertex, FGEdge> visualGraph = graphViewer.getVisualGraph();
		Collection<FGVertex> visualGraphVertices = visualGraph.getVertices();
		
		//System.out.println("Starting instrumentation injection into Function Graph Vertex ListingPanel components");
		
		//Iterate through all vertices and attach listeners to each internal ListingPanel
		for(FGVertex vertex : visualGraphVertices) {
			//Grab the top level ListingPanel component of the graph vertex
			JComponent component = vertex.getComponent();
			Component[] clist = component.getComponents();
			
			//Iterate through the component list and pull out the correct component... ordering is likely not guaranteed
			FGVertexListingPanel listingPanel = (FGVertexListingPanel)CavaUtils.findJComponentByClass(FGVertexListingPanel.class, clist);
			
			//Instrument the listingPanel in an identical manner to the CavaCodeBrowser
			instrumentationStatus = CavaUtils.instrumentListingView(cavaComponentName+"_ListingPanel", listingPanel, true);
		}
		
		//Return success if all vertex components were instrumented
		return instrumentationStatus;
	}
	
	/**
	 * Add listeners for graph vertex components. 
	 * 
	 * The following events are currently supported: 
	 * 
	 * - FunctionGraphZoomEvent on double-clicks if the zoom/scale has changed
	 * 
	 * @param graphViewer
	 */
	private void addGraphMouseListeners(GraphViewer<FGVertex, FGEdge> graphViewer) {
		//Add mouse listeners directly to graph vertices
		graphViewer.addGraphMouseListener(new GraphMouseListener<FGVertex>() {

			@Override
			public void graphClicked(FGVertex vertex, MouseEvent event) {
				//System.out.println(">>>> GraphMouseListener: Graph Clicked");

				if(event.getClickCount()>1) {
					//Double clicking on vertex will zoom/unzoom the graph
					//System.out.println(">>>> GraphMouseListener: Graph Double Clicked");
					checkGraphScaleChanged(graphViewer, cavaComponentName, event);
				}
				
				VertexMouseInfo<FGVertex, FGEdge> vertexMouseInfo = GraphViewerUtils.convertMouseEventToVertexMouseEvent(graphViewer, event);
				if(vertexMouseInfo != null) {
					GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphVertexClickEvent(cavaComponentName, event, graphViewer);
					CavaEventPublisher.publishNewEvent(ghidraEvent);
				}
			}

			@Override
			public void graphPressed(FGVertex vertex, MouseEvent event) {
				// TODO Auto-generated method stub
				//System.out.println(">>>> GraphMouseListener: Graph Pressed");
			}

			@Override
			public void graphReleased(FGVertex vertex, MouseEvent event) {
				// TODO Auto-generated method stub
				//System.out.println(">>>> GraphMouseListener: Graph Released");
			}
		});
	}
	
	/**
	 * 	
	 * Add mouse listeners for various Function Graph interactions
	 * 
	 * The following events are currently supported: 
	 * 
	 * - FunctionGraphZoomEvent on double-clicks if the zoom/scale has changed
	 * - FunctionGraphEdgePickEvent on select or unselect of graph edges
	 * 
	 * @param graphViewer
	 */
	private void addMouseListeners(GraphViewer<FGVertex, FGEdge> graphViewer) {
		
		//Collect additional details concerning the graph and picked edges
		graphViewer.addMouseListener(new MouseListener() {

			@Override
			public void mouseClicked(MouseEvent event) {
				//System.out.println(">>>> MouseListener: Mouse Clicked");
				//---------------------- Look for Edge Picked State --------------------
				
				//On Mouse clicks, get the set of picked edges and details
				PickedState<FGEdge> pickedState = graphViewer.getPickedEdgeState();
				Set<FGEdge> pickedEdges = pickedState.getPicked();
				//System.out.println(">>>> Number of picked edges:"+pickedEdges.size());
								
				//Added edges
				Set<FGEdge> addedEdges = new HashSet<FGEdge>(pickedEdges);
				addedEdges.removeAll(currentPickedEdges);
				//System.out.println(">>>> Added picked edge count:"+addedEdges.size());

				for(FGEdge edge : addedEdges) {
					GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphEdgePickedEvent(cavaComponentName, event, graphViewer, edge);
					CavaEventPublisher.publishNewEvent(ghidraEvent);
				}
				
				//Removed edges
				Set<FGEdge> removedEdges = new HashSet<FGEdge>(currentPickedEdges);
				removedEdges.removeAll(pickedEdges);
				//System.out.println(">>>> Removed picked edge count:"+removedEdges.size());
				
				for(FGEdge edge : removedEdges) {
					
					GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphEdgeUnPickedEvent(cavaComponentName, event, graphViewer, edge);
					CavaEventPublisher.publishNewEvent(ghidraEvent);
				}
				
				//Update our list of picked edges
				currentPickedEdges = new HashSet<FGEdge>(pickedEdges);
				
				//System.out.println(pickedEdges.toString());
			}

			@Override
			public void mousePressed(MouseEvent e) {
				// TODO Auto-generated method stub
				//System.out.println(">>>> MouseListener: Mouse Pressed");
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				// TODO Auto-generated method stub
				//System.out.println(">>>> MouseListener: Mouse Released");
			}

			@Override
			public void mouseEntered(MouseEvent e) {
				// TODO Auto-generated method stub
				//System.out.println(">>>> MouseListener: Mouse Entered");
			}

			@Override
			public void mouseExited(MouseEvent e) {
				// TODO Auto-generated method stub
				//System.out.println(">>>> MouseListener: Mouse Exited");
			}
		});
	}
	
	
	/**
	 * Add mouse motion listeners for mouse dragged and move events. 
	 * 
	 * The following events are currently supported: 
	 * 
	 * - FunctionGraphVertexDragEvent if dragging the grab area of a vertex
	 * - FunctionGraphHoverEvent if the mouse moves while over a graph vertex or exits hover status over a graph vertex
	 * 
	 * Not yet supported:
	 * - Pop-over events in which the mouse movement triggers and overlay/pop-over view
	 * 
	 * @param graphViewer
	 */
	private void addMouseMotionListeners(VisualGraphView<FGVertex, FGEdge, FunctionGraph> visualGraphView) {
		GraphViewer<FGVertex, FGEdge> graphViewer = visualGraphView.getPrimaryGraphViewer();
		
		graphViewer.addMouseMotionListener(new MouseMotionListener() {

			@Override
			public void mouseDragged(MouseEvent event) {
				//System.out.println(">>>> MouseMotionListener: Mouse Dragged");				

				VertexMouseInfo<FGVertex, FGEdge> vertexMouseInfo = GraphViewerUtils.convertMouseEventToVertexMouseEvent(graphViewer, event);
				if(vertexMouseInfo == null) { return; }
				
				if(vertexMouseInfo.isGrabArea()) {
					//If the mouse is dragged and mouse is on the drag area, this is in implicit move of a vertex of the graph
					GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphVertexDragEvent(cavaComponentName, event, graphViewer);
					CavaEventPublisher.publishNewEvent(ghidraEvent);
					return;
				}
			}

			@Override
			public void mouseMoved(MouseEvent event) {
				//System.out.println(">>>> MouseMotionListener: Mouse Moved");

				//-------------------------- Vertex Hover Events ------------------------------
				//Emit vertex hover events if the mouse is over a vertex				
				VertexMouseInfo<FGVertex, FGEdge> vertexMouseInfo = GraphViewerUtils.convertMouseEventToVertexMouseEvent(graphViewer, event);
				
				FGVertex vertex;
				if(vertexMouseInfo == null) { 
					vertex=null; 
				} else {
					vertex = vertexMouseInfo.getVertex();
				}
				
				if(vertex == null) { 
					//Emit event with null vertex if we have 'exited' a previous hover
					if(lastHoveredVertex != null) { 
						lastHoveredVertex = null;
						GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphVertexHoverEndEvent(cavaComponentName, event, graphViewer);
						CavaEventPublisher.publishNewEvent(ghidraEvent);
					}
					//Emit no event if the vertex is null and we were not just hovered
				} else if(vertex != lastHoveredVertex) { 
					//If we have already emitted a hover event for this vertex, skip it 

					//Emit a hover event for new hover event
					GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphVertexHoverStartEvent(cavaComponentName, event, graphViewer);
					CavaEventPublisher.publishNewEvent(ghidraEvent);	
					lastHoveredVertex = vertex;
				}
			}
		});
	}
	
	
	/**
	 * Add mouse wheel listener to check for zoom/scaling events
	 * The following events are currently supported: 
	 * 
	 * - FunctionGraphZoomEvent if the mouse wheel is used within the graph view if the zoom/scale has changed
	 * 
	 * @param graphViewer
	 */
	private void addMouseWheelListener(GraphViewer<FGVertex, FGEdge> graphViewer) {
		graphViewer.addMouseWheelListener(new MouseWheelListener() {

			@Override
			public void mouseWheelMoved(MouseWheelEvent event) {
				//System.out.println(">>>> MouseWheelListener: Mouse Wheel Moved");
				//Check for change in graph scale/zoom
				checkGraphScaleChanged(graphViewer, cavaComponentName, event);
			}
		});
	}
	
	
	/**
	 * Checks whether the graph scale has been changed and 
	 * generates a new event if the graph scale has changed. 
	 * 
	 * @param graphViewer
	 * @param event
	 */
	
	private void checkGraphScaleChanged(GraphViewer<FGVertex, FGEdge> graphViewer, String _cavaComponentName, MouseEvent event) {
		double newGraphScale = GraphViewerUtils.getGraphScale(graphViewer);
		
		//If zoom hasn't changed do not generate an event
		if(newGraphScale == graphScale) { return; }
		
		//TODO: we should extend this to capture non-mouse zoom events... keypresses, menu interactions, etc
		if(event instanceof MouseWheelEvent) {
			GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphMouseWheelZoomEvent(_cavaComponentName, (MouseWheelEvent)event, graphViewer, graphScale);
			CavaEventPublisher.publishNewEvent(ghidraEvent);
		} else {
			GhidraEvent<?> ghidraEvent = GhidraEvent.generateFunctionGraphMouseClickZoomEvent(_cavaComponentName, event, graphViewer, graphScale);
			CavaEventPublisher.publishNewEvent(ghidraEvent);
		}
		
		graphScale = newGraphScale;
	}
}
