package cavalistener;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;

import java.awt.Color;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.time.Instant;
import java.util.Formatter;
import java.util.Locale;

import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;

/**
 * JPanel intended to be presented to a subject with task instructions and controls for continuing to the next task. 
 * 
 * This panel should be modified for use within other experiments requiring a different interface (or no interface). 
 * 
 * The current version of the panel provides additional information such as a live time-stamp which is useful in ensuring 
 * captured screen recording information can be associated with the correct time-stamp without dealing with video
 * timing and keyframe information. 
 * 
 * @author Sunny J. Fugate
 */
public class TaskSequencingPanel extends JPanel {
	public JTextField taskResult;
	public JLabel taskNumber;
	public JLabel taskName;
	public JTextPane taskInstructions;
	public JButton actionButton;
	private JScrollPane scrollPane;

	String cavaComponentName = "CavaTaskSequencingPanel";
	
	public void updateTaskFields(CavaTask task,TaskState taskState) {
		taskName.setText(TaskState.getTaskNameText(task));
		taskNumber.setText(TaskState.getTaskNumberText(task));
		taskResult.setText("");
		taskInstructions.setText(TaskState.getTaskInstructionsText(task));	
		taskInstructions.setCaretPosition(0);
		
		updateTaskFields(taskState);
	}
	
	public void updateTaskFields(TaskState taskState) {
		actionButton.setText(taskState.label);
	}
	
	/**
	 * Create the Task Sequencing panel.
	 */
	public TaskSequencingPanel() {
		setForeground(Color.WHITE);
		
		taskNumber = new JLabel("n/a");
		taskNumber.setHorizontalAlignment(SwingConstants.LEFT);
		
		JLabel taskLabel = new JLabel("Task:");
		taskLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		
		taskName = new JLabel("n/a");
		taskName.setHorizontalAlignment(SwingConstants.LEFT);
		
		JLabel taskInstructionsLabel = new JLabel("Instructions:");
		taskInstructionsLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		
		JLabel taskResultLabel = new JLabel("Result:");
		taskResultLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		
		taskResult = new JTextField();
		taskResult.setColumns(10);
		
		//Add instrumentation for the result text area, tracking mouse entry/exit, clicks, presses, etc
		CavaEventListener.instrumentMouseInteraction("CavaTaskSequencingPanel_TaskResultTextPane", taskResult);
		
		actionButton = new JButton("New button");
		actionButton.setFont(new Font("Dialog", Font.PLAIN, 12));
		
		//Add instrumentation for the action/next button, tracking mouse entry/exit, clicks, presses, etc
		CavaEventListener.instrumentMouseInteraction("CavaTaskSequencingPanel_ActionButton", actionButton);
		
		scrollPane = new JScrollPane();
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		JScrollBar verticalScrollBar = scrollPane.getVerticalScrollBar();
		
		//Add instrumentation for the vertical scroll bar to track when user is scrolling instructions.
		CavaEventListener.instrumentVerticalScrollbarAdjustment(cavaComponentName, verticalScrollBar);

		//New JLabel for keeping track of the time, we update the text in the timer function below.
		JLabel txtTime = new JLabel("Time: ");
		txtTime.setHorizontalAlignment(SwingConstants.LEFT);
		
		final Timer clockTimer = new Timer(100, (ActionEvent e) -> {
			String epochTime = getEpochTime();
			txtTime.setText("Time: " + epochTime);
		});
		clockTimer.setRepeats(true);
		clockTimer.start();		
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING, false)
						.addComponent(taskInstructionsLabel, GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
						.addComponent(taskResultLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(taskLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
					.addGap(9)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(taskResult, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(actionButton, GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE))
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(taskNumber, GroupLayout.PREFERRED_SIZE, 36, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(taskName, GroupLayout.DEFAULT_SIZE, 57, Short.MAX_VALUE)
							.addGap(36)
							.addComponent(txtTime, GroupLayout.PREFERRED_SIZE, 185, GroupLayout.PREFERRED_SIZE))
						.addGroup(groupLayout.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(scrollPane, GroupLayout.DEFAULT_SIZE, 320, Short.MAX_VALUE)))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(taskName)
						.addComponent(taskNumber)
						.addComponent(taskLabel)
						.addComponent(txtTime, GroupLayout.PREFERRED_SIZE, 15, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(taskInstructionsLabel)
						.addComponent(scrollPane, GroupLayout.DEFAULT_SIZE, 235, Short.MAX_VALUE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(taskResultLabel)
						.addComponent(taskResult, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(actionButton))
					.addGap(1))
		);
		
		taskInstructions = new JTextPane();
		scrollPane.setViewportView(taskInstructions);
		//Make sure that the task instructions panel is not editable.
		taskInstructions.setEditable(false);

		//Add instrumentation for the panel itself, tracking mouse entry/exit, clicks, presses, etc
		CavaEventListener.instrumentMouseInteraction("CavaTaskSequencingPanel_TaskInstructionsTextPane", taskInstructions);
		
		setLayout(groupLayout);

	}

	/**
	 * Clear the task fields, setting the values to "n/a". 
	 * 
	 * These values are presented to the subject in the task interface
	 * and can be modified as needed for different experiments.  
	 * Also see TaskState.java 
	 */
	public void clearTaskFields() {
		this.taskNumber.setText("n/a");
		this.taskName.setText("n/a");
		this.taskInstructions.setText("n/a");
		this.taskResult.setText("");
	}
	
	/**
	 * Returns the Unix time as a String
	 * 
	 * @return String Unix timestamp
	 */
	String getEpochTime() {
		Instant now = Instant.now();
		double val=now.getEpochSecond() + ((double)now.getNano()) / 1000_000_000;
		Formatter fmt = new Formatter(Locale.US); 
		fmt.format("%.7f", val);
		String value = fmt.toString();
		fmt.close();
		return value;
	}
}
