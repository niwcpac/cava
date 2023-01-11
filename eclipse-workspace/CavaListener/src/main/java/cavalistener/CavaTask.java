package cavalistener;

import java.util.Arrays;
import java.util.UUID;

/**
 * Data class for experimental tasks intended to be read from the cava-tasks 
 * folder and mapped to this object directly from JSON.
 * 
 * @author Sunny J. Fugate
 */
public class CavaTask implements Comparable<CavaTask> {

	private int sequence; // numeric sequence number for task ordering generated when task sequence is first loaded
	
	private String name; // name of the task
	private String instructions; // instructions for display to subject
	
	private String program; // name of the challenge binary problem
	private String start; // starting address for the task
	private String end; // ending address for the task (if any)
	
	private String surveytasks;

	private int taskID;
	private int trialID;
	private String taskUUID; // a universally unique identifier, generated on first request
	
	private boolean autoSeek; // boolean to indicate whether the tool should seek to the specified address (or starting address)
	
	private boolean survey; // boolean to indicate whether a post-survey should be used for this subtask
	
	private String answerKey; // Not Applicable, Vulnerable, Not Vulnerable

	// List of addresses that directly relate to the defect or empty if this program is Not Applicable
	// This array may also contain addresses that may potentially be vulnerable, allowing measurements of proximity to suspicious locations
	private String[][] keyAddresses = new String[2][]; 

	private String expectedResponse;
	
	/**
	 * Create an empty CavaTask
	 */
	public CavaTask() {
		return;
	}
	
	/**
	 * Create a CavaTask with the given name, sequence number, and instructions
	 * @param name
	 * @param sequence
	 * @param instructions
	 */
	public CavaTask(String name, int sequence, String instructions) {
		this.name=name;
		this.sequence=sequence;
		this.instructions=instructions;
	}
	
	/**
	 * Compare two CavaTasks and indicate their order. 
	 * @param task
	 * @return 0 if equal, 1 if the indicated task occurs before, -1 if the indicated task occurs after
	 */
	@Override
	public int compareTo(CavaTask task) {
		if(task.sequence == sequence) {
			return 0;
		} else if(sequence > task.sequence) {
			return 1;
		} else { //sequenceNumber < task.sequenceNumber
			return -1;
		}
	}
	
	public String getStart() 						{ return start; }
	public void setStart(String start) 				{ this.start = start; }
	
	public String getEnd() 							{ return end; }
	public void setEnd(String end) 					{ this.end = end; }
	
	public String getName() 						{ return name; }
	public void setName(String name) 				{ this.name = name; }
	
	public String getProgram() 						{ return program; }
	public void setProgram(String problem) 			{ this.program = problem; }
	
	public String getInstructions() 					{ return instructions; }
	public void setInstructions(String instructions) 	{ this.instructions = instructions; }
	
	public int getSequence() 						{ return sequence; }
	public void setSequence(int sequence) 			{ this.sequence = sequence; }
	
	public boolean getSurvey()						{ return survey; }
	public void setSurvey(boolean survey)			{ this.survey = survey; }
	
	public boolean getAutoSeek()						{ return autoSeek; }
	public void setAutoSeek(boolean autoSeek)		{ this.autoSeek = autoSeek; }
	
	public String getSurveytasks()					{ return surveytasks; }
	public void setSurveytasks(String surveytasks) 	{ this.surveytasks = surveytasks; }
	
	public int getTaskID()							{ return taskID; }
	public void setTaskID(int taskID)				{ this.taskID = taskID; }
	
	public int getTrialID()							{ return trialID; }
	public void setTrialID(int trialID)				{ this.trialID = trialID; }
	
	public String getAnswerKey()					{ return answerKey; }
	public void setAnswerKey(String answerKey)		{ this.answerKey = answerKey; }
	
	public String[][] getKeyAddresses() 				{ return keyAddresses; }
	public void setKeyAddresses(String[][] keyAddresses) { this.keyAddresses = keyAddresses; }
	
	public String getExpectedResponse()				{ return expectedResponse; }
	public void setExpectedResponse(String expectedResponse) { this.expectedResponse = expectedResponse; }
	
	
	/**
	 * Returns a UUID generated upon first retrieval to uniquely identify this
	 * specific instance of the task.  The intent is for the UUID to be referenced within
	 * other instrumentation to ensure other data refers back to the current task. 
	 * @return a universally unique identifier
	 */
	public String getTaskUUID() {
		if(taskUUID==null) {
			taskUUID=UUID.randomUUID().toString();
		}
		
		return taskUUID; 
	}
	//NOTE: Do not prove a setter to prevent this field from being set externally
	//public void setTaskUUID(String taskUUID) 	{ this.taskUUID = taskUUID; }
	
	@Override
	public String toString() {
		
		String theKeyAddresses = Arrays.toString(keyAddresses);
		StringBuilder builder = new StringBuilder();
		builder.append("Sequence: "+sequence);
		builder.append(", Name: "+name);		
		builder.append(", Program:"+program);
		builder.append(", Start:"+start);
		builder.append(", End:"+end);
		builder.append(", AutoSeek:"+autoSeek);
		builder.append(", TaskID: "+taskID);
		builder.append(", TrialID: "+trialID);
		builder.append(", TaskUUID:"+taskUUID);
		builder.append(", Survey:"+survey);
		builder.append(", SurveyTasks:"+surveytasks);
		builder.append(", AnswerKey:"+answerKey);
		builder.append(", KeyAddresses:"+theKeyAddresses);
		builder.append(", ExpectedResponse:"+expectedResponse);
		builder.append(", Instructions:"+instructions);
		
		return builder.toString();
	}
}
