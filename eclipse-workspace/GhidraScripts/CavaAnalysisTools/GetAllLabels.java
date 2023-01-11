//Extracts all changed labels on the currently loaded program.
//@author Froylan Maldonado
//@category CAVA_ANALYSIS
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.model.symbol.SymbolTable;

/*
 * 
 * The main logic for the script is as follows:
 * 
 * The first thing we need to know is that all label information is managed by the symbol table object. 
 * This object contains the label history for all labels in the loaded program. What this program does 
 * is load all the labels in the program and iterates through them. We decide which labels to 
 * log by checking the Unix time of when the label history object was created. The time-stamp to use to filter 
 * should be the first time-stamp in the lsl_data.json file.
 * 
 * Something to note is that the initial labels functions have for variables aren't actual labels. 
 * For example, if we rename variable iVar2 -> newVarName, the label history object will *not* have 
 * iVar2 stored anywhere. This is probably due to how Ghidra Decompiler works so there's nothing much we can
 * do about that. This means that the output of this script will have the original label name be completely wrong; 
 * the original label according to the history will be something along the lines of "LOCAL_RAX_2".
 * 
 * @author Froylan Maldonado
 * 
 */
public class GetAllLabels extends GhidraScript {

	@Override
	protected void run() throws Exception {
		
		SymbolTable symtable = currentProgram.getSymbolTable();
		long filter = askLong("Please input a unix timestamp to use as a filter", "Unix Time in Seconds");
		Iterator<LabelHistory> it = symtable.getLabelHistory();
		
		File  dir = askDirectory("Please select a folder to output labels", "Select");
		File output = new File(dir, "labels_"+currentProgram.getName()+".txt");
		
		PrintWriter printwriter = new PrintWriter(new FileWriter(output));
		
		while(it.hasNext()) {
			LabelHistory curr = it.next();
			// Java creates the Unix time in milliseconds, must convert to seconds.
			long time = curr.getModificationDate().getTime() / 1000;
			if(time > filter) {
				JsonObject labelEvent = new JsonObject();
				// ActionID == 2 means that this label history object corresponds to a label change
				if(curr.getActionID() == 2) {
					JsonObject labelData = new JsonObject();
					// Label changes have the following label string format "ORIGINAL_LABEL to NEW_LABEL"
					// Will always have this format since we check for ActionID
					String[] changes = curr.getLabelString().split(" ");
					// Might not be the original label due to how Ghidra Decompiler operates
					labelData.addProperty("OriginalLabel", changes[0]);
					labelData.addProperty("NewLabel", changes[2]);
					labelData.addProperty("Address", curr.getAddress().toString(false, false));
					labelData.addProperty("Timestamp", time);
					labelEvent.add("LabelEvent", labelData);
					printwriter.println(labelEvent.toString());
				}
			}
		}
		printwriter.close();
	}
}
