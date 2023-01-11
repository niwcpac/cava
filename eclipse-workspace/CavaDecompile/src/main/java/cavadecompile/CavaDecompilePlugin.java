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
package cavadecompile;

import java.awt.Component;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;

import cavalistener.CavaEventListener;
import cavalistener.CavaUtils;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.ClipboardService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * This plugin is a small extension to the standard Decompiler plugin in which interactions
 * with the decompiler are instrumented for purposes of human subjects experimentation.
 * 
 * The goal of this extension is to provide sufficient instrumentation of the plugin to provide insights 
 * into how a subject interacts with the decompiler. 
 * 
 * @author Sunny J. Fugate
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Instrumented Decompiler",
	description = "Provides the Decompiler with additional instrumentation",
	servicesRequired = { 
			GoToService.class, NavigationHistoryService.class, ClipboardService.class, 
			DataTypeManagerService.class /*, ProgramManager.class */
	},
	eventsConsumed = { 
		ProgramActivatedPluginEvent.class, ProgramOpenedPluginEvent.class, 
		ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class, 
		ProgramClosedPluginEvent.class
	}
)
//@formatter:on
public class CavaDecompilePlugin extends DecompilePlugin {
	String cavaComponentName = "CavaDecompilePlugin";
	
	/*
	ComponentProvider decompilerProvider;
	CavaDecompileProvider cavaDecompileProvider;
	*/
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CavaDecompilePlugin(PluginTool tool) {
		super(tool);
		
		
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
		
		//cavaDecompileProvider= new CavaDecompileProvider(this.tool);
		

	}
	
	
	public void addCavaEventListeners() {
		
		//Obtain the tool's active component provider
		//ComponentProvider decompilerProvider = tool.getComponentProvider("Decompiler");
		List<DecompilerProvider> providers = tool.getWindowManager().getComponentProviders(DecompilerProvider.class);
		
		//TODO: Behavior is unknown/undefined if there are two loaded DecompilePlugin instances... 
		
		DecompilerProvider connectedProvider = null;
		for(DecompilerProvider provider : providers) { //Search for the active provider
			if(provider.isVisible()) {
				connectedProvider = provider;
				System.out.println("(Re)-Instrumented the Decompiler");
				break;
			}
		}
		/* TODO: Address whether number of instrumented providers may grow large and cause performance issues
		 * if they are not disposed of and garbage collected when not used
		 * That is, the number providers might grow unbounded due to the core plugin maintains a list 
		 * of 'disconnected' providers.  This may be a non-issue as the instrumentation code isn't called
		 * unless the provider is active, so other than a small memory cost may be moot. 
		 */
		
		if(connectedProvider == null) { 
			System.out.println("Could not instrument Decompiler, no visible DecomplerProvider found");
			return; 
		}
		
		//Obtain the top level component for the provider
		//All other components will hang off of this one, somewhere
		JComponent decoratorPanel = connectedProvider.getComponent();

		
		Component[] clist1 = decoratorPanel.getComponents();
		DecompilerPanel decompilerPanel = (DecompilerPanel)CavaUtils.findJComponentByClass(DecompilerPanel.class, clist1);
		Component[] clist2 = decompilerPanel.getComponents();
		IndexedScrollPane indexedScrollPane = (IndexedScrollPane)CavaUtils.findJComponentByClass(IndexedScrollPane.class, clist2);
		
		Component[] clist3 = indexedScrollPane.getComponents();
		JScrollPane jScrollPane = (JScrollPane)CavaUtils.findJComponentByClass(JScrollPane.class,clist3);
		
		JScrollBar verticalScrollBar = jScrollPane.getVerticalScrollBar();
		CavaEventListener.instrumentVerticalScrollbarAdjustment(cavaComponentName, verticalScrollBar);
		
		JScrollBar horizontalScrollBar = jScrollPane.getHorizontalScrollBar();
		CavaEventListener.instrumentHorizontalScrollbarAdjustment(cavaComponentName, horizontalScrollBar);
		
		//Component[] clist4 = jScrollPane.getComponents();

		//-----------------------------------------------------------
		// Instrument FieldPanel
		FieldPanel fieldPanel = decompilerPanel.getFieldPanel();
		
		// Add generic mouse listener for the field panel itself
		CavaEventListener.instrumentMouseInteraction(cavaComponentName, fieldPanel);
				
		// Add listeners for field interaction events
		CavaEventListener.instrumentFieldMouse(cavaComponentName, fieldPanel);
		CavaEventListener.instrumentFieldLocation(cavaComponentName, fieldPanel);
		CavaEventListener.instrumentFieldSelection(cavaComponentName, fieldPanel);
		CavaEventListener.instrumentFieldInput(cavaComponentName, fieldPanel);
	}
	
	
	
	@Override 
	public void processEvent(PluginEvent pluginEvent) {
		super.processEvent(pluginEvent);
		
		if(pluginEvent instanceof ProgramLocationPluginEvent) {
			//Add dynamic instrumentation
			//System.out.println("Decompile ProgramLocationPluginEvent");
			addCavaEventListeners();
		}
	}
	
	
	
}
