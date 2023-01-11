package cavalistener;

/**
 * Enum for state tracking of task sequences and providing GUI strings
 * 
 * @author Sunny J. Fugate
 */
enum TaskState {
	INITIALIZE("Click when ready to begin"),
	START("Start task"),
	FINISH("Enter response and finish task"),
	SURVEY("Click to take task survey"),
	NEXT("Load next task"),
	COMPLETE("All tasks are completed.");
	
	public final String label;
	private TaskState(String label) {
		this.label=label;
	}
	
	public static String getTaskNameText(CavaTask task) { 	
		if(task==null) { return "n/a"; }
		return task.getName();
	}
	public static String getTaskNumberText(CavaTask task) {
		if(task==null) { return "n/a"; }
		return String.valueOf(task.getSequence());
	}
	public static String getTaskInstructionsText(CavaTask task) {
		if(task==null) { return "n/a"; }
		return task.getInstructions();
	}
}
