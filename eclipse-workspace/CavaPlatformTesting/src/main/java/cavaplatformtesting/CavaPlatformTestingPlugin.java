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
package cavaplatformtesting;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Simple empty plugin to use as a placeholder when testing. 
 * This plugin is the skeleton generated by GhidraDev without modification.
 * 
 * In Eclipse this plugin is set to be dependent on all other 
 * plugins that should be built and installed into Ghidra during 
 * development. 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class CavaPlatformTestingPlugin extends Plugin {

	MyProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CavaPlatformTestingPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
