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
package cavacodebrowser;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.Timer;

import cavalistener.CavaUtils;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.events.ViewChangedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.ClipboardService;
import ghidra.app.services.CodeFormatService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.FieldMouseHandlerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;


/**
 * This plugin is an extension to the standard Code Browser plugin in which interactions
 * with the code browser are instrumented for purposes of human subjects experimentation.
 * 
 * The goal of this extension is to provide sufficient instrumentation of the plugin to provide insights 
 * into how a subject interacts with the code browser. 
 * 
 * @author Sunny J. Fugate
 */
//@formatter:off
@PluginInfo(
		status = PluginStatus.UNSTABLE,
		packageName = CorePluginPackage.NAME,
		category = PluginCategoryNames.CODE_VIEWER,
		shortDescription = "Instrumented Code Viewer",
		description = "Provides a CodeViewer with additional instrumentation",
		servicesRequired = { ProgramManager.class, GoToService.class, ClipboardService.class /*, TableService.class */ },
		servicesProvided = { CodeViewerService.class, CodeFormatService.class, FieldMouseHandlerService.class },
		eventsConsumed = { ProgramSelectionPluginEvent.class, ProgramActivatedPluginEvent.class,
			ProgramClosedPluginEvent.class, ProgramLocationPluginEvent.class,
			ViewChangedPluginEvent.class, ProgramHighlightPluginEvent.class },
		eventsProduced = { ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class }
	)
//@formatter:on
public class CavaCodeBrowserPlugin extends CodeBrowserPlugin {

	CodeViewerProvider provider;
	String cavaComponentName = "CavaCodeBrowserPlugin";
	boolean instrumentationStatus = false;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CavaCodeBrowserPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();	
		provider = this.getProvider();
	}
	
	/**
	 * Process various plugin events. 
	 * 
	 * Note: make sure to allow the superclass to process events 
	 * or literally nothing will work in the original plugin functionality. 
	 */
	@Override
	public void processEvent(PluginEvent pluginEvent) {
		super.processEvent(pluginEvent);
		
		//TODO: We should look into dynamic instrumentation where PluginEvents triggers validation of injected instrumentation
		
		if(pluginEvent instanceof ProgramActivatedPluginEvent) {
			System.out.println("Program Activated, injecting instrumentation");
			provider = this.getProvider();
			
			//Call recursive function to add event listeners
			addCavaEventListeners();
			
		} 
	}
	
	
	/**
	 * CAVA instrumentation initializer is implemented as a recursive function with a 
	 * delay using a Timer task.  This is intended to address issues where a component is not yet ready
	 * resulting in instrumentation failure.  The prior fix was just to add a longer delay
	 * but this is problematic as may still fail in instances with high system load, larger 
	 * programs loaded into Ghidra, etc.  The solution here is to attempt instrumentation
	 * and if it fails to then call the function again a short time later.  The worst case 
	 * scenario for instrumentation is that the function will be called indefinitely, but
	 * will output an error message on each failure. 
	 * 
	 * TODO: There are some odd interactions between this extended plugin and
	 * the default CodeViewerPlugin in which if the other viewer
	 * is loaded then the new viewer does not load all of the window 
	 * features (e.g. NavigationMarkers on the right or the arrow block indicators on the left. 
	 * 
	 * TODO: Have a second CodeBrowser instance also breaks our static instrumentation.  
	 * Unloading the offending plugin resolves the issue, but is not a great fix.  
	 * 
	 * @author Sunny Fugate
	 */
	public void addCavaEventListeners() {
		ListingPanel listingPanel = this.getListingPanel();
		boolean status = false;

		/* It is not our job to be idempotent, we will rely on the CavaEventListener class to deal with this */
		if(instrumentationStatus == true) {
			System.out.println("CavaCodeBrowser was already instrumented but addCavaEventListeners was called again... attempting re-instrumentation.");
		}
		
		System.out.println("Attempting instrumentation injection into "+cavaComponentName);
		status = CavaUtils.instrumentListingView(cavaComponentName, listingPanel, false);				
		System.out.println(cavaComponentName+" instrumented completed with status: "+status);
		
		//If instrumentation has succeeded, return
		if(status==true) { instrumentationStatus=true; return; }
		
		//-------------------------------------------------------------------------
		//If instrumentation fails, create a TimerTask and try again at a later time
	
		//Action listener for delayed instrumentation
		ActionListener actionListener=new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				addCavaEventListeners();
			}
		};
		
		//Use a timer to delay listener initialization.  This attempts to fix a  
		//race conditions in static instrumentation where the component isn't constructed yet. 
		Timer instrumentationTask = new Timer(1000, actionListener);
		instrumentationTask.setRepeats(false);
		instrumentationTask.start();	
	}	

}

