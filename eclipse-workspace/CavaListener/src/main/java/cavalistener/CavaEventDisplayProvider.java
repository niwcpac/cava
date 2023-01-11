package cavalistener;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.plugintool.*;
import docking.action.DockingAction;
import docking.widgets.EventTrigger;

/**
 * Display provider for the CavaListener which shows
 * statistics and time-stamps for recently transmitted
 * user interface events. 
 * 
 * @author Sunny Fugate
 *
 */
public class CavaEventDisplayProvider extends ComponentProviderAdapter {
	@SuppressWarnings("unused")
    private DockingAction startAction;

	private JPanel outerPanel;
	
	private TaskSequencingPanel taskSequencingPanel;

	private CavaListenerPlugin plugin;
	
	SortedSet<CavaTask> taskSequence = new TreeSet<CavaTask>();
	boolean taskSequenceReady = false;
	Iterator<CavaTask> taskSequenceIterator;
	@SuppressWarnings("unused")
    private int taskCount=0;
	
	private CavaTask currentTask;
	private CavaTaskSurveyResults currentTaskSurveyResults;
	
	private TaskState taskState = TaskState.INITIALIZE;

	@SuppressWarnings("unused")
    private GhidraLocationChangedEvent lastGhidraLocationChangedEvent;

	public CavaEventDisplayProvider(CavaListenerPlugin plugin, PluginTool tool, String name) {
		super(tool, name, name);
		
		this.plugin=plugin;
		//TODO: prevent cava listener plugin from closing
		//tool.getToolFrame().setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		outerPanel = new JPanel();
		outerPanel.setLayout(new GridLayout(0,1));
		//Create the task sequence panel and attach it to the JPanel. Use "WindowBuilder" to make changes to this!
		taskSequencingPanel = new TaskSequencingPanel();
		outerPanel.add(taskSequencingPanel);
		taskSequencingPanel.updateTaskFields(currentTask,taskState);
		
		taskSequencingPanel.actionButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				processTaskStateTransition();
			}
		});
		/*
		outerPanel.add(taskNumber);
		outerPanel.add(taskName);
		outerPanel.add(taskAnswer);
		outerPanel.add(taskInstructions);
		outerPanel.add(actionButton);
		*/
		setTitle("Task Instructions");
		setVisible(true);
		//TODO: find way of disabling the 'close' button / dockingAction
		//createAction(); Disable toolbar actions
		//Remove the 'close' docking action
		/*
		Set<DockingActionIf> actionSet = this.getTool().getDockingActionsByOwnerName("CavaEvetDisplayProvider");
		// getdockingTool.getAllActions();
		for(DockingActionIf action : actionSet) {
			System.out.println(action.getFullName());
			//if(action.)
			//this.dockingTool.removeAction(action);
		}
		*/	
		//TODO: Use ZXing to generate a 2d barcode/QR code that contains the event data, at minimum the specific event ID/Sequence number
	}
	
	public void processTaskStateTransition() {
		switch(taskState) {
		case INITIALIZE:
			startTaskSequence();
			if(!taskSequenceReady) {
				System.out.println("Task sequence could not be loaded.");
				//something is wrong... task sequence could not be loaded
				break;
			}
			//Send GhidraEvent to the event publisher
			GhidraEvent<?> initializeEvent = GhidraEvent.generateTaskInitializeEvent(CavaListenerPlugin.class.getSimpleName(),EventTrigger.GUI_ACTION);
			CavaEventPublisher.publishNewEvent(initializeEvent);
			
			//Reset to the starting address in case the view had been shifted/changed prior to start.
			plugin.goToStartingAddress();
			
			taskState = TaskState.START;
			taskSequencingPanel.clearTaskFields();
			currentTask=taskSequenceIterator.next();
			CavaPerformanceMetrics.updateTaskData(currentTask);
			taskSequencingPanel.updateTaskFields(currentTask,taskState);
			taskSequencingPanel.taskInstructions.setText("Click start button below when ready"); //blank out the task description until start
			break;
		case START:
			//Send GhidraEvent to the event publisher
			GhidraEvent<?> startEvent = GhidraEvent.generateTaskStartEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.GUI_ACTION, currentTask);
			CavaEventPublisher.publishNewEvent(startEvent);

			//If specified, set the active program
			String programName = currentTask.getProgram();
			if(programName != null) {
				System.out.println("Setting Active Program to:"+currentTask.getProgram());
				plugin.setActiveProgram(currentTask.getProgram());
			}
			
			//Reset GhidraLocation to the starting address if autoSeek is specified
			if(currentTask.getAutoSeek()) {
				if(currentTask.getStart().isEmpty()) { //Empty task start seeks to starting address
					plugin.goToStartingAddress();
				} else { //Otherwise seek to the specified address
					plugin.goToSpecifiedAddress(currentTask.getStart());
				}
			} //Otherwise, leave the Ghidra location alone
			
			taskState = TaskState.FINISH;
			taskSequencingPanel.updateTaskFields(currentTask, taskState);
			break;
		case FINISH:
			String resultText = taskSequencingPanel.taskResult.getText();
			
			if(resultText.length() == 0) { //Check if the task is finished (prevent spurious button clicks by requiring text entry)
				//Generate task incomplete event
				GhidraEvent<?> incompleteEvent = GhidraEvent.generateTaskIncompleteEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.GUI_ACTION, currentTask, "Message Dialog: Please enter a result to continue.");
				CavaEventPublisher.publishNewEvent(incompleteEvent);
				
				JOptionPane.showMessageDialog(null, "Please enter a result value to continue.");
				break;
			}
			
			//Send GhidraEvent to the event publisher
			GhidraEvent<?> finishEvent = GhidraEvent.generateTaskFinishEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.GUI_ACTION, currentTask, resultText);
			CavaEventPublisher.publishNewEvent(finishEvent);
			
			if(currentTask.getSurvey()) { //Proceed to the survey step if required
				taskState = TaskState.SURVEY;
				taskSequencingPanel.updateTaskFields(taskState);
				taskSequencingPanel.taskInstructions.setText("Click on survey button below when ready");
				currentTaskSurveyResults = new CavaTaskSurveyResults(currentTask);
			} else { //Skip the survey if the survey boolean is not set
				taskState = TaskState.NEXT;
				taskSequencingPanel.clearTaskFields();
				taskSequencingPanel.updateTaskFields(taskState);
			}
			break;
		case SURVEY:
			//If the survey is not complete and if the survey flag is set
			if(!currentTaskSurveyResults.isCompleted) {
				System.out.println("Survey is starting.");
				
				GhidraEvent<?> surveyStartEvent = GhidraEvent.generateTaskSurveyStartEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.GUI_ACTION, currentTask);
				CavaEventPublisher.publishNewEvent(surveyStartEvent);
				
				//Launch the survey dialog
				CavaTaskSurveyDialog taskSurveyDialog = new CavaTaskSurveyDialog(this,currentTaskSurveyResults);
				taskSurveyDialog.setVisible(true); //Test if necessary
				
				
				break; //break out, we aren't done yet, survey hasn't been completed
			}
			
			//Survey should be complete, finish up 
			
			//Send GhidraEvent with the survey results
			GhidraEvent<?> surveyFinishEvent = GhidraEvent.generateTaskSurveyFinishEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.GUI_ACTION, currentTask, currentTaskSurveyResults);
			CavaEventPublisher.publishNewEvent(surveyFinishEvent);
			
			taskState = TaskState.NEXT;
			taskSequencingPanel.clearTaskFields();
			taskSequencingPanel.updateTaskFields(taskState);
			break;
		case NEXT:
			if(taskSequenceIterator.hasNext()) {
				//Send GhidraEvent to indicate user has requested next task
				GhidraEvent<?> nextEvent = GhidraEvent.generateTaskNextEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.GUI_ACTION, currentTask);
				CavaEventPublisher.publishNewEvent(nextEvent);
			
				taskState = TaskState.START;
				taskSequencingPanel.clearTaskFields();
				currentTask=taskSequenceIterator.next();
				CavaPerformanceMetrics.updateTaskData(currentTask);

				taskSequencingPanel.updateTaskFields(currentTask,taskState);
				taskSequencingPanel.taskInstructions.setText("Click start button below when ready"); //blank out the task description until start
				break;
			} //else fall through to default... sequence is complete
		default:
			//Send GhidraEvent to indicate user has requested next task, and sequence is complete
			GhidraEvent<?> taskCompleteEvent = GhidraEvent.generateExperimentCompleteEvent(CavaListenerPlugin.class.getSimpleName(), EventTrigger.INTERNAL_ONLY);
			CavaEventPublisher.publishNewEvent(taskCompleteEvent);
			
			taskState = TaskState.COMPLETE;
			currentTask=null;
			CavaPerformanceMetrics.updateTaskData(currentTask);
			taskSequencingPanel.updateTaskFields(currentTask,taskState);
			break;
		}
	}

	@Override
	public JComponent getComponent() {
		return outerPanel;
	}

	
	public void processEvent(GhidraEvent<?> event) {
		
		if(event instanceof GhidraLocationChangedEvent) {
			this.lastGhidraLocationChangedEvent = (GhidraLocationChangedEvent)event;
			//this.lastGhidraLocationChangedEvent.byteAddress;
		}
		/*
		eventTime.setText(String.valueOf(event.getTimestamp()));
		eventName.setText(" : "+event.getEventName());
		
		printLocationDetails(event.get);
		*/
	}
	

	/*
	private void printLocationDetails(PluginEvent event) {
		if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent l = (ProgramLocationPluginEvent) event;
			ProgramLocation location = l.getLocation();
			textArea.append("\t" + location.toString());
			textArea.append("\n");
		}
	}
	*/

	
	/*
	private void createAction() {
		startAction = new DockingAction("Load Task Sequence", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(taskState == TaskState.INITIALIZE) {
					//Start new task sequence
					startTaskSequence();
					return;
				} 
				System.out.println("Attempted to reload task sequence, but no longer at initialization state");
			}
		};

		startAction.markHelpUnnecessary();
		startAction.setEnabled(true);
		ImageIcon icon = ResourceManager.loadImage("images/play.png");
		startAction.setToolBarData(new ToolBarData(icon));
		addLocalAction(startAction);
	}
	*/
	
	
	
	/**
	 * On first run, this loads and then initiates the task sequence. 
	 */
	private void startTaskSequence() {		
		//Task sequence is not yet ready, initialize from source
		initializeCavaTaskSequence();
		
		//Show the task sequence interface if tasks were loaded properly
		if(!taskSequenceReady) { 
			System.out.println("Task sequence failed to load properly");
			return;
		}
		//Check that we actually have tasks in our sequence
		if(taskSequence.size() < 1) {
			System.out.println("Task sequence file was parsed, but is empty");
			return;
		}
		
		//Grab the iterator for the SortedSet/TreeSet
		this.taskSequenceIterator = this.taskSequence.iterator();
	}
	
	/**
	 * Parse a JSON representation of the experimental tasks from file.
	 */
	public void initializeCavaTaskSequence() {
		try {
			//TODO: make this configurable.. 
			///TODO: this path will currently break in the dev environment I think,perhaps use a symlink? 
			Path taskSequencePath = Paths.get("/vagrant/cava-tasks/cava-task-sequence.txt");
			System.out.println("Attempting to fetch Cava Task Sequence from file: "+taskSequencePath.toAbsolutePath());
			List<String> taskList;
			try (Stream<String> lines = Files.lines(Paths.get("/vagrant/cava-tasks/cava-task-sequence.txt"))) {
				taskList = lines.collect(Collectors.toList());
			} catch (Exception e){
				//Bail out with an error if the file is missing or we have issues reading it
				System.out.println("!! Failed to read task sequence file: "+taskSequencePath.toString());
				this.taskSequenceReady = false;
				e.printStackTrace();
				return;
			}
			
			//Bail if we were unable to read the file
			if(taskSequence == null) { 
				this.taskSequenceReady=false; 
				return; 
			}
			
			int sequenceNumber=1;
			
			Pattern accept = Pattern.compile("^[A-Za-z0-9_]*\\s*"); //Match all valid task names (alphanumeric with underscores, no spaces)
			Pattern skip = Pattern.compile("^\\s*#.*|^\\s*$"); //Match all comments for which the first non-whitespace character is a # or only whitespace
			//Reject any string which is not in accept or skip
			ObjectMapper mapper = new ObjectMapper();
			for(String taskName : taskList ) {
				taskName = taskName.replaceAll("\\s+$",  ""); //Remove trailing whitespace
				
				Matcher m = skip.matcher(taskName);
				if(m.matches()) { 
					//Skipping comment in cava-task-sequence.txt file
					System.out.println("Skipping empty line or comment: ["+taskName+"]");
					continue; 
				} 
				m = accept.matcher(taskName);
				if(!m.matches()) { //If we do not match our accept regex, bail with an error
					System.out.println("!!! Line in cava-task-sequence file did not match expected pattern:["+accept.pattern()+"]. Dumping error to log and bailing");
					System.out.println("!!! Rejected line: ["+taskName+"]"); //probably should go to stderr?
					this.taskSequenceReady = false;
					return;
				}
				
				CavaTask task;
				try {
					Path taskMetadata = Paths.get("/vagrant/cava-tasks/"+taskName+"-metadata.json");
					task = mapper.readValue(taskMetadata.toFile(), new TypeReference<CavaTask>() {});
				} catch (FileNotFoundException e) {
					System.out.println("!! Could not read the task metadata for task ["+taskName+"]. Dumping error to log and bailing");
					e.printStackTrace();
					this.taskSequenceReady = false;
					return;
				}
				
				String taskInstructions;
				try {
					Path taskInstructionPath = Paths.get("/vagrant/cava-tasks/"+taskName+"-instructions.txt");
					taskInstructions = Files.readString(taskInstructionPath);
				} catch(Exception e) {
					System.out.println("!! Could not read task instructions for task ["+taskName+"]. Dumping error to log and bailing");
					e.printStackTrace();
					this.taskSequenceReady = false;
					return;
				}
				
				task.setInstructions(taskInstructions);
				task.setSequence(sequenceNumber);
				
				//Import into our SortedSet
				this.taskSequence.add(task);
				
				sequenceNumber = sequenceNumber + 1;
				System.out.println(task.toString());
			}
		} catch (Exception e) {
			System.out.println("!! Failed to load task sequence information.  Dumping error to log and bailing");
			this.taskSequenceReady = false;
			e.printStackTrace();
			return;
		}
		
		//TODO: send entire task sequence as Cava Event?
		this.taskSequenceReady=true;
	}

}