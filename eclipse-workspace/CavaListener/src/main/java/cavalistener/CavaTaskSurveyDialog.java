package cavalistener;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;

import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.RowSpec;
import com.jgoodies.forms.layout.FormSpecs;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextArea;

/**
 * JDialog class used for intra-task surveys. 
 * 
 * When editing this class, we recommend using the Eclipse Window Builder since this was how it was created. 
 * 
 * This survey dialog was manually constructed with hard-coded values. 
 * A good generalization would be to load the survey from a JSON file and generate a 
 * new survey based on the desired questions. This could be done on a per-task basis. 
 * 
 * @author Sunny J. Fugate
 */
public class CavaTaskSurveyDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();

	CavaTaskSurveyResults surveyResults;
	CavaEventDisplayProvider cavaEventDisplayProvider;
	
	ButtonGroup r1 = new ButtonGroup();
	ButtonGroup r2 = new ButtonGroup();
	ButtonGroup r3 = new ButtonGroup();
	private String q1Scale = "1: very difficult; 4: neutral; 7: very easy";
	private String q2Scale = "1: not confident at all; 4: somewhat confident; 7: fully confident";
	private String q3Scale = "1: no strategy; 7: precise strategy";

	private JLabel q1;
	private JLabel q1Low;
	private JLabel q1Mid;
	private JLabel q1High;
	private JLabel q2;
	private JLabel q2Low;
	private JLabel q2Mid;
	private JLabel q2High;
	private JLabel q3;
	private JLabel q3Low;
	private JLabel q3High;
	private JTextArea q3Comment;
	

	/**
	 * Create the JDialog
	 * @param cavaEventDisplayProvider
	 * @param surveyResults
	 */
	public CavaTaskSurveyDialog(CavaEventDisplayProvider cavaEventDisplayProvider, CavaTaskSurveyResults surveyResults) {
		super(cavaEventDisplayProvider.getTool().getActiveWindow(), Dialog.ModalityType.APPLICATION_MODAL);
		this.cavaEventDisplayProvider = cavaEventDisplayProvider;
		this.surveyResults = surveyResults;
		setBounds(100, 100, 960, 527);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.WEST);
		contentPanel.setLayout(new FormLayout(new ColumnSpec[] {
				FormSpecs.RELATED_GAP_COLSPEC,
				FormSpecs.DEFAULT_COLSPEC,
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("center:50dlu:grow"),
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("center:50dlu"),
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("center:default"),
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("center:50dlu"),
				FormSpecs.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("center:50dlu"),
				FormSpecs.RELATED_GAP_COLSPEC,
				FormSpecs.DEFAULT_COLSPEC,},
			new RowSpec[] {
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				RowSpec.decode("default:grow"),
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,
				FormSpecs.RELATED_GAP_ROWSPEC,
				FormSpecs.DEFAULT_ROWSPEC,}));
		{
			q1 = new JLabel("The task was easy to complete in the time provided.");
			contentPanel.add(q1, "2, 2, 9, 1");
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 4, 13, 1");
		}
		{
			q1Low = new JLabel("Very difficult");
			contentPanel.add(q1Low, "2, 6, center, default");
		}
		{
			q1Mid = new JLabel("Neutral");
			contentPanel.add(q1Mid, "8, 6, center, default");
		}
		{
			q1High = new JLabel("Very easy");
			contentPanel.add(q1High, "14, 6, center, default");
		}
		{
			JRadioButton q1r1 = new JRadioButton("1");
			q1r1.setActionCommand("1");
			contentPanel.add(q1r1, "2, 8, center, default");
			r1.add(q1r1);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r1", q1r1);
		}
		{
			JRadioButton q1r2 = new JRadioButton("2");
			q1r2.setActionCommand("2");
			contentPanel.add(q1r2, "4, 8, center, default");
			r1.add(q1r2);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r2", q1r2);
		}
		{
			JRadioButton q1r3 = new JRadioButton("3");
			q1r3.setActionCommand("3");
			contentPanel.add(q1r3, "6, 8, center, default");
			r1.add(q1r3);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r3", q1r3);
		}
		{
			JRadioButton q1r4 = new JRadioButton("4");
			q1r4.setActionCommand("4");
			contentPanel.add(q1r4, "8, 8, center, default");
			r1.add(q1r4);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r4", q1r4);
		}
		{
			JRadioButton q1r5 = new JRadioButton("5");
			q1r5.setActionCommand("5");
			contentPanel.add(q1r5, "10, 8, center, default");
			r1.add(q1r5);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r5", q1r5);
		}
		{
			JRadioButton q1r6 = new JRadioButton("6");
			q1r6.setActionCommand("6");
			contentPanel.add(q1r6, "12, 8");
			r1.add(q1r6);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r6", q1r6);
		}
		{
			JRadioButton q1r7 = new JRadioButton("7");
			q1r7.setActionCommand("7");
			contentPanel.add(q1r7, "14, 8, center, default");
			r1.add(q1r7);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q1r7", q1r7);
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 10, 13, 1");
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 12, 13, 1");
		}
		{
			q2 = new JLabel("I am confident in having found the right answer for this task.");
			contentPanel.add(q2, "2, 16, 9, 1");
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 18, 13, 1");
		}
		{
			q2Low = new JLabel("Not confident at all");
			contentPanel.add(q2Low, "2, 20, center, default");
		}
		{
			q2Mid = new JLabel("Somewhat confident");
			contentPanel.add(q2Mid, "8, 20");
		}
		{
			q2High = new JLabel("Fully confident");
			contentPanel.add(q2High, "14, 20, center, default");
		}
		{
			JRadioButton q2r1 = new JRadioButton("1");
			q2r1.setActionCommand("1");
			contentPanel.add(q2r1, "2, 22, center, default");
			r2.add(q2r1);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r1", q2r1);
		}
		{
			JRadioButton q2r2 = new JRadioButton("2");
			q2r2.setActionCommand("2");
			contentPanel.add(q2r2, "4, 22, center, default");
			r2.add(q2r2);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r2", q2r2);
		}
		{
			JRadioButton q2r3 = new JRadioButton("3");
			q2r3.setActionCommand("3");
			contentPanel.add(q2r3, "6, 22, center, default");
			r2.add(q2r3);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r3", q2r3);
		}
		{
			JRadioButton q2r4 = new JRadioButton("4");
			q2r4.setActionCommand("4");
			contentPanel.add(q2r4, "8, 22, center, default");
			r2.add(q2r4);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r4", q2r4);
		}
		{
			JRadioButton q2r5 = new JRadioButton("5");
			q2r5.setActionCommand("5");
			contentPanel.add(q2r5, "10, 22, center, default");
			r2.add(q2r5);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r5", q2r5);
		}
		{
			JRadioButton q2r6 = new JRadioButton("6");
			q2r6.setActionCommand("6");
			contentPanel.add(q2r6, "12, 22");
			r2.add(q2r6);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r6", q2r6);
		}
		{
			JRadioButton q2r7 = new JRadioButton("7");
			q2r7.setActionCommand("7");
			contentPanel.add(q2r7, "14, 22, center, default");
			r2.add(q2r7);
			
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q2r7", q2r7);
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 24, 13, 1");
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 26, 13, 1");
		}
		{
			q3 = new JLabel("I had a strategy or methodology for completing this task.");
			contentPanel.add(q3, "2, 30, 9, 1");
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 32, 13, 1");
		}
		{
			q3Low = new JLabel("No strategy");
			contentPanel.add(q3Low, "2, 34, center, default");
		}
		{
			q3High = new JLabel("Precise strategy");
			contentPanel.add(q3High, "14, 34");
		}
		{
			JRadioButton q3r1 = new JRadioButton("1");
			q3r1.setActionCommand("1");
			contentPanel.add(q3r1, "2, 36, center, default");
			r3.add(q3r1);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r1", q3r1);
		}
		{
			JRadioButton q3r2 = new JRadioButton("2");
			q3r2.setActionCommand("2");
			contentPanel.add(q3r2, "4, 36");
			r3.add(q3r2);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r2", q3r2);
		}
		{
			JRadioButton q3r3 = new JRadioButton("3");
			q3r3.setActionCommand("3");
			contentPanel.add(q3r3, "6, 36");
			r3.add(q3r3);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r3", q3r3);
		}
		{
			JRadioButton q3r4 = new JRadioButton("4");
			q3r4.setActionCommand("4");
			contentPanel.add(q3r4, "8, 36, center, default");
			r3.add(q3r4);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r4", q3r4);
		}
		{
			JRadioButton q3r5 = new JRadioButton("5");
			q3r5.setActionCommand("5");
			contentPanel.add(q3r5, "10, 36");
			r3.add(q3r5);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r5", q3r5);
		}
		{
			JRadioButton q3r6 = new JRadioButton("6");
			q3r6.setActionCommand("6");
			contentPanel.add(q3r6, "12, 36");
			r3.add(q3r6);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r6", q3r6);
		}
		{
			JRadioButton q3r7 = new JRadioButton("7");
			q3r7.setActionCommand("7");
			contentPanel.add(q3r7, "14, 36, center, default");
			r3.add(q3r7);
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3r7", q3r7);
		}
		{
			JSeparator separator = new JSeparator();
			contentPanel.add(separator, "2, 38, 13, 1");
		}
		{
			JLabel q3CommentLabel = new JLabel("Please describe some details of the method that you used for the task:");
			contentPanel.add(q3CommentLabel, "2, 40, 5, 1");
		}
		{
			q3Comment = new JTextArea();
			q3Comment.setLineWrap(true);
			q3Comment.setWrapStyleWord(true);
			
			contentPanel.add(q3Comment, "4, 42, 11, 7, fill, fill");
			CavaEventListener.instrumentMouseInteraction("TaskSurvey_q3Comment", q3Comment);

		}
		

		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("Submit Responses");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						storeSurveyResults();
					}
				});
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
				CavaEventListener.instrumentMouseInteraction("TaskSurvey_SubmitResponses", okButton);

			}
		}
	}
	
	/**
	 * Store the survey results and dispose of the dialog
	 */
	private void storeSurveyResults() {
		ButtonModel r1m = r1.getSelection();
		ButtonModel r2m = r2.getSelection();
		ButtonModel r3m = r3.getSelection();
		//Check that all radio button groups have values
		if(	r1m == null || r2m == null || r3m == null ) {
			JOptionPane.showMessageDialog(null, "Please provide a response to each question.");
			return;
		}
		
		//Parse and package the survey results
		this.surveyResults.setQ1(this.q1.getText(), r1m.getActionCommand(), "", this.q1Scale); //No comment field
		this.surveyResults.setQ2(this.q2.getText(), r2m.getActionCommand(), "", this.q2Scale); //No comment field
		this.surveyResults.setQ3(this.q3.getText(), r3m.getActionCommand(), q3Comment.getText(), this.q3Scale);
		
		this.surveyResults.isCompleted=true;
		this.cavaEventDisplayProvider.processTaskStateTransition();
		dispose();
	}

}
