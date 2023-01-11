//Gets all comments from a loaded program and outputs them to a specified directory.
//@author Froylan Maldonado
//@category CAVA_ANALYSIS
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentHistory;
import ghidra.program.model.listing.Listing;

/*
 * 
 * The main logic of the script is as follows:
 * 
 * We extract all the code units in the program using the loaded listing object. This allows us to iterate through all
 * addresses in the program. Once we have an address of interest, we get the commentHistory object that pertains to that address.
 * Once we have that, we then get the comment history for each type of comment since they are stored separately.
 * After that, we then check the time-stamp of when the comment was made and see if it's after the Unix time-stamp filter that
 * is user defined. If it is, then we log the comment information.
 * 
 * @author Froylan Maldonado
 * 
 */

public class GetAllComments extends GhidraScript {

	private void writeToFile(PrintWriter printwriter, CommentHistory[] commentHistory, long filter) {
		int length = commentHistory.length;
		for (int k = 0; k < length; k++) {
			JsonObject commentEvent = new JsonObject();
    		JsonObject commentRecord = new JsonObject();
    		long timestamp = commentHistory[k].getModificationDate().getTime() / 1000;
			if (timestamp < filter) {
				continue;
			}
			String comment = commentHistory[k].getComments();
			commentRecord.addProperty("Comment", comment);
			commentRecord.addProperty("Timestamp", timestamp);
			commentRecord.addProperty("Address", commentHistory[k].getAddress().toString());
			commentEvent.add("CavaCommentEvent", commentRecord);
			printwriter.println(commentEvent.toString());
    	}
	}
	
	@Override
	protected void run() throws Exception {
		
		Listing listing = currentProgram.getListing();
		CodeUnitIterator allCodeUnits = listing.getCodeUnits(true);
		long filter = askLong("Timestamp", "Please Enter a timestamp to filter comments by.");
		File dir = askDirectory("Select where to output comment file.", "Select");
		File output = new File(dir, "comments_"+currentProgram.getName()+"_txt");
		PrintWriter printwriter = new PrintWriter(new FileWriter(output));

		allCodeUnits.forEach((currCodeUnit) -> {
			Address currAddress = currCodeUnit.getMinAddress();
			while (currCodeUnit.contains(currAddress)) {
				CommentHistory[] eolCommentHistory = listing.getCommentHistory(currAddress, CodeUnit.EOL_COMMENT);
	        	CommentHistory[] plateCommentHistory= listing.getCommentHistory(currAddress, CodeUnit.PLATE_COMMENT);
	        	CommentHistory[] postCommentHistory = listing.getCommentHistory(currAddress, CodeUnit.POST_COMMENT);
	        	CommentHistory[] preCommentHistory = listing.getCommentHistory(currAddress, CodeUnit.PRE_COMMENT);
	        	writeToFile(printwriter, eolCommentHistory, filter);
	        	writeToFile(printwriter, plateCommentHistory, filter);
	        	writeToFile(printwriter, postCommentHistory, filter);
	        	writeToFile(printwriter, preCommentHistory, filter);
	        	currAddress = currAddress.next();
	        	if(currAddress == null) {
	        		break;
	        	}
			}
		});
		printwriter.close();
	}
}
