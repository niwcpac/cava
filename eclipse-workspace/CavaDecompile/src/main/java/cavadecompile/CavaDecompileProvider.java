package cavadecompile;

import java.awt.event.KeyEvent;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class CavaDecompileProvider extends ComponentProviderAdapter {
	CavaDockingAction testAction;
	
	public CavaDecompileProvider(PluginTool tool) {
		super(tool, "CavaDecompileProvider", "CavaDecompileProvider");
		
		testAction = new CavaDockingAction();
		addLocalAction(testAction);
	}

	class CavaDockingAction extends DockingAction {
		public CavaDockingAction() {
			super("Cava Instrumentation Test", "CavaActionListener");
			
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_Z, 0));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			// TODO Auto-generated method stub
			System.out.println("ActionInsturmenter test: "+this.getKeyBinding());
			
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return true;
		}
	}

	@Override
	public JComponent getComponent() {
		// TODO Auto-generated method stub
		return null;
	}
			
	/*
		//"Cava Keystroke Instrumentation Test", "CavaActionListenerTest") {
		@Override
		public void actionPerformed(ActionContext context) {
			
		}
		
	};
	*/
}
