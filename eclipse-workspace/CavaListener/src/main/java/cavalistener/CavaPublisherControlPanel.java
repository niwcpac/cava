package cavalistener;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JCheckBox;
import javax.swing.JTextField;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;

/**
 * Unused class to manage the CAVA Publisher interface. 
 * 
 * This has been used in testing, but has not been re-incorporated into the CavaListener plugin.
 * This class should probably be moved to its own plugin context. 
 *
 * @author Sunny J. Fugate
 */
public class CavaPublisherControlPanel extends JTabbedPane {
	private JTextField lslSourceIdTextField;
	private JTextField lslStreamNameTextField;
	private JCheckBox  lslEnableCheckbox;
	
	private JTextField udpDestAddressTextField;
	private JTextField udpDestPortTextField;
	private JTextField udpSourcePortTextField;
	private JCheckBox udpEnableCheckbox;
	
	private JTextField tcpDestAddressTextField;
	private JTextField tcpDestPortTextField;
	private JTextField tcpSourcePortTextField;
	private JCheckBox tcpEnableCheckbox;
	
	private JTextField logfileLocationTextField;
	private JCheckBox  logfileEnableCheckbox;
	
	private JCheckBox stdoutEnableCheckbox;
	

	//-------------- LSL Settings ----------------
	public String get_lslSourceId() {
		return lslSourceIdTextField.getText();
	}
	public String get_lslStreamName() {
		return lslStreamNameTextField.getText();
	}
	public Boolean get_lslEnable() {
		return lslEnableCheckbox.isSelected();
	}
	
	//-------------- UDP Settings ----------------
	public String get_udpDestAddress() {
		return udpDestAddressTextField.getText();
	}
	public String get_udpDestPort() {
		return udpDestPortTextField.getText();
	}
	public Boolean get_udpEnable() {
		return udpEnableCheckbox.isSelected();
	}
	
	//--------------- TCP Settings -----------------
	public String get_tcpDestAddress() {
		return tcpDestAddressTextField.getText();
	}
	public String get_tcpDestPort() {
		return tcpDestPortTextField.getText();
	}
	public String get_tcpSourcePort() {
		return tcpSourcePortTextField.getText();
	}
	
	//--------------- Logfile Settings ------------
	public String get_logfileLocation() {
		return logfileLocationTextField.getText();
	}
	public Boolean get_logfileEnable() {
		return logfileEnableCheckbox.isSelected();
	}
	
	//--------------- StdOut Settings --------------
	public Boolean get_stdoutEnable() {
		return stdoutEnableCheckbox.isSelected();
	}

	
	/**
	 * Panel constructor
	 */
	public CavaPublisherControlPanel() {
		
		//------------ LSL Panel ----------------
		JPanel lsl_panel=new JPanel();
		addTab("LSL",lsl_panel);
		
		GridBagLayout gbl1 = new GridBagLayout();
		gbl1.columnWidths = new int[] {150, 0, 0};
		gbl1.rowHeights = new int[]{15, 15, 0, 23, 0, 0};
		gbl1.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};

		lsl_panel.setLayout(gbl1);
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = 2;
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.insets = new Insets(0, 0, 5, 0);
		gbc.gridx = 0;
		gbc.gridy = 0;
		lsl_panel.add(new JLabel("Send events to Lab Streaming Layer"), gbc);
		
		GridBagConstraints gbc_lslSourceIdLabel = new GridBagConstraints();
		gbc_lslSourceIdLabel.anchor = GridBagConstraints.EAST;
		gbc_lslSourceIdLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lslSourceIdLabel.gridx = 0;
		gbc_lslSourceIdLabel.gridy = 1;
		JLabel lslSourceIdLabel = new JLabel("Source ID");
		lsl_panel.add(lslSourceIdLabel, gbc_lslSourceIdLabel);
		
		lslSourceIdTextField = new JTextField();
		GridBagConstraints gbc_lslSourceIdTextField = new GridBagConstraints();
		gbc_lslSourceIdTextField.anchor = GridBagConstraints.WEST;
		gbc_lslSourceIdTextField.insets = new Insets(0, 0, 5, 0);
		gbc_lslSourceIdTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_lslSourceIdTextField.gridx = 1;
		gbc_lslSourceIdTextField.gridy = 1;
		lsl_panel.add(lslSourceIdTextField, gbc_lslSourceIdTextField);
		lslSourceIdTextField.setColumns(10);
		
		JLabel lslStreamNameLabel = new JLabel("Stream Name");
		GridBagConstraints gbc_lslStreamNameLabel = new GridBagConstraints();
		gbc_lslStreamNameLabel.anchor = GridBagConstraints.EAST;
		gbc_lslStreamNameLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lslStreamNameLabel.gridx = 0;
		gbc_lslStreamNameLabel.gridy = 2;
		lsl_panel.add(lslStreamNameLabel, gbc_lslStreamNameLabel);
		
		lslStreamNameTextField = new JTextField();
		GridBagConstraints gbc_lslStreamNameTextField = new GridBagConstraints();
		gbc_lslStreamNameTextField.anchor = GridBagConstraints.WEST;
		gbc_lslStreamNameTextField.insets = new Insets(0, 0, 5, 0);
		gbc_lslStreamNameTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_lslStreamNameTextField.gridx = 1;
		gbc_lslStreamNameTextField.gridy = 2;
		lsl_panel.add(lslStreamNameTextField, gbc_lslStreamNameTextField);
		lslStreamNameTextField.setColumns(10);
		
		
		lslEnableCheckbox = new JCheckBox("Enable");
		GridBagConstraints gbc_lslEnableCheckbox = new GridBagConstraints();
		gbc_lslEnableCheckbox.anchor = GridBagConstraints.EAST;
		gbc_lslEnableCheckbox.gridx = 1;
		gbc_lslEnableCheckbox.gridy = 4;
		lsl_panel.add(lslEnableCheckbox, gbc_lslEnableCheckbox);
		
		//------------------- UDP Panel ------------------------
		JPanel udp_panel=new JPanel();
		addTab("UDP", udp_panel);
		
		GridBagLayout gbl2 = new GridBagLayout();
		gbl2.columnWidths = new int[] {150, 0, 0};
		gbl2.rowHeights = new int[]{15, 15, 0, 23, 0, 0};
		gbl2.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl2.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};

		udp_panel.setLayout(gbl2);
		
		GridBagConstraints gbc_udpPaneTitle = new GridBagConstraints();
		gbc_udpPaneTitle.insets = new Insets(0, 0, 5, 0);
		gbc_udpPaneTitle.anchor = GridBagConstraints.NORTH;
		gbc_udpPaneTitle.gridwidth = 2;
		gbc_udpPaneTitle.gridx = 0;
		gbc_udpPaneTitle.gridy = 0;
		JLabel udpPaneTitle = new JLabel("Send events using UDP socket");
		udp_panel.add(udpPaneTitle, gbc_udpPaneTitle);
		
		JLabel udpDestAddressLabel = new JLabel("Dest Address");
		GridBagConstraints gbc_udpDestAddressLabel = new GridBagConstraints();
		gbc_udpDestAddressLabel.anchor = GridBagConstraints.EAST;
		gbc_udpDestAddressLabel.insets = new Insets(0, 0, 5, 5);
		gbc_udpDestAddressLabel.gridx = 0;
		gbc_udpDestAddressLabel.gridy = 1;
		udp_panel.add(udpDestAddressLabel, gbc_udpDestAddressLabel);
		
		udpDestAddressTextField = new JTextField();
		udpDestAddressTextField.setColumns(10);
		GridBagConstraints gbc_udpDestAddressTextField = new GridBagConstraints();
		gbc_udpDestAddressTextField.insets = new Insets(0, 0, 5, 0);
		gbc_udpDestAddressTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_udpDestAddressTextField.gridx = 1;
		gbc_udpDestAddressTextField.gridy = 1;
		udp_panel.add(udpDestAddressTextField, gbc_udpDestAddressTextField);
		
		JLabel udpDestPortLabel = new JLabel("Dest Port");
		GridBagConstraints gbc_udpDestPortLabel = new GridBagConstraints();
		gbc_udpDestPortLabel.anchor = GridBagConstraints.EAST;
		gbc_udpDestPortLabel.insets = new Insets(0, 0, 5, 5);
		gbc_udpDestPortLabel.gridx = 0;
		gbc_udpDestPortLabel.gridy = 2;
		udp_panel.add(udpDestPortLabel, gbc_udpDestPortLabel);
		
		udpDestPortTextField = new JTextField();
		udpDestPortTextField.setColumns(10);
		GridBagConstraints gbc_udpDestPortTextField = new GridBagConstraints();
		gbc_udpDestPortTextField.insets = new Insets(0, 0, 5, 0);
		gbc_udpDestPortTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_udpDestPortTextField.gridx = 1;
		gbc_udpDestPortTextField.gridy = 2;
		udp_panel.add(udpDestPortTextField, gbc_udpDestPortTextField);
		
		JLabel udpSourcePortLabel = new JLabel("Source Port");
		GridBagConstraints gbc_udpSourcePortLabel = new GridBagConstraints();
		gbc_udpSourcePortLabel.anchor = GridBagConstraints.EAST;
		gbc_udpSourcePortLabel.insets = new Insets(0, 0, 5, 5);
		gbc_udpSourcePortLabel.gridx = 0;
		gbc_udpSourcePortLabel.gridy = 3;
		udp_panel.add(udpSourcePortLabel, gbc_udpSourcePortLabel);
		
		udpSourcePortTextField = new JTextField();
		udpSourcePortTextField.setColumns(10);
		GridBagConstraints gbc_udpSourcePortTextField = new GridBagConstraints();
		gbc_udpSourcePortTextField.insets = new Insets(0, 0, 5, 0);
		gbc_udpSourcePortTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_udpSourcePortTextField.gridx = 1;
		gbc_udpSourcePortTextField.gridy = 3;
		udp_panel.add(udpSourcePortTextField, gbc_udpSourcePortTextField);
		
		udpEnableCheckbox = new JCheckBox("Enable");
		GridBagConstraints gbc_udpEnableCheckbox = new GridBagConstraints();
		gbc_udpEnableCheckbox.anchor = GridBagConstraints.EAST;
		gbc_udpEnableCheckbox.gridx = 1;
		gbc_udpEnableCheckbox.gridy = 4;
		udp_panel.add(udpEnableCheckbox, gbc_udpEnableCheckbox);
		
		//------------------- TCP Panel -----------------------------
		JPanel tcp_panel = new JPanel();
		addTab("TCP", tcp_panel);
		
		GridBagLayout gbl3 = new GridBagLayout();
		gbl3.columnWidths = new int[] {150, 0, 0};
		gbl3.rowHeights = new int[]{15, 15, 0, 23, 0, 0};
		gbl3.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl3.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};

		tcp_panel.setLayout(gbl3);
		
		
		JLabel tcpPaneTitle = new JLabel("Send events using TCP socket");
		GridBagConstraints gbc_tcpPaneTitle = new GridBagConstraints();
		gbc_tcpPaneTitle.anchor = GridBagConstraints.NORTH;
		gbc_tcpPaneTitle.gridwidth = 2;
		gbc_tcpPaneTitle.insets = new Insets(0, 0, 5, 0);
		gbc_tcpPaneTitle.gridx = 0;
		gbc_tcpPaneTitle.gridy = 0;
		tcp_panel.add(tcpPaneTitle, gbc_tcpPaneTitle);
		
		JLabel tcpDestAddressLabel = new JLabel("Dest Address");
		GridBagConstraints gbc_tcpDestAddressLabel = new GridBagConstraints();
		gbc_tcpDestAddressLabel.anchor = GridBagConstraints.EAST;
		gbc_tcpDestAddressLabel.insets = new Insets(0, 0, 5, 5);
		gbc_tcpDestAddressLabel.gridx = 0;
		gbc_tcpDestAddressLabel.gridy = 1;
		tcp_panel.add(tcpDestAddressLabel, gbc_tcpDestAddressLabel);
		
		tcpDestAddressTextField = new JTextField();
		tcpDestAddressTextField.setColumns(10);
		GridBagConstraints gbc_tcpDestAddressTextField = new GridBagConstraints();
		gbc_tcpDestAddressTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_tcpDestAddressTextField.anchor = GridBagConstraints.WEST;
		gbc_tcpDestAddressTextField.insets = new Insets(0, 0, 5, 0);
		gbc_tcpDestAddressTextField.gridx = 1;
		gbc_tcpDestAddressTextField.gridy = 1;
		tcp_panel.add(tcpDestAddressTextField, gbc_tcpDestAddressTextField);
		
		JLabel tcpDestPortLabel = new JLabel("Dest Port");
		GridBagConstraints gbc_tcpDestPortLabel = new GridBagConstraints();
		gbc_tcpDestPortLabel.anchor = GridBagConstraints.EAST;
		gbc_tcpDestPortLabel.insets = new Insets(0, 0, 5, 5);
		gbc_tcpDestPortLabel.gridx = 0;
		gbc_tcpDestPortLabel.gridy = 2;
		tcp_panel.add(tcpDestPortLabel, gbc_tcpDestPortLabel);
		
		tcpDestPortTextField = new JTextField();
		tcpDestPortTextField.setColumns(10);
		GridBagConstraints gbc_tcpDestPortTextField = new GridBagConstraints();
		gbc_tcpDestPortTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_tcpDestPortTextField.insets = new Insets(0, 0, 5, 0);
		gbc_tcpDestPortTextField.gridx = 1;
		gbc_tcpDestPortTextField.gridy = 2;
		tcp_panel.add(tcpDestPortTextField, gbc_tcpDestPortTextField);
		
		JLabel tcpSourcePortLabel = new JLabel("Source Port");
		GridBagConstraints gbc_tcpSourcePortLabel = new GridBagConstraints();
		gbc_tcpSourcePortLabel.anchor = GridBagConstraints.EAST;
		gbc_tcpSourcePortLabel.insets = new Insets(0, 0, 5, 5);
		gbc_tcpSourcePortLabel.gridx = 0;
		gbc_tcpSourcePortLabel.gridy = 3;
		tcp_panel.add(tcpSourcePortLabel, gbc_tcpSourcePortLabel);
		
		tcpSourcePortTextField = new JTextField();
		tcpSourcePortTextField.setColumns(10);
		GridBagConstraints gbc_tcpSourcePortTextField = new GridBagConstraints();
		gbc_tcpSourcePortTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_tcpSourcePortTextField.insets = new Insets(0, 0, 5, 0);
		gbc_tcpSourcePortTextField.gridx = 1;
		gbc_tcpSourcePortTextField.gridy = 3;
		tcp_panel.add(tcpSourcePortTextField, gbc_tcpSourcePortTextField);
		
		tcpEnableCheckbox = new JCheckBox("Enable");
		GridBagConstraints gbc_tcpEnableCheckbox = new GridBagConstraints();
		gbc_tcpEnableCheckbox.anchor = GridBagConstraints.EAST;
		gbc_tcpEnableCheckbox.gridx = 1;
		gbc_tcpEnableCheckbox.gridy = 4;
		tcp_panel.add(tcpEnableCheckbox, gbc_tcpEnableCheckbox);

		//--------------- StdOut Panel -------------------
		JPanel stdoutPanel=new JPanel();
		add(stdoutPanel,"StdOut");
		
		GridBagLayout gbl4 = new GridBagLayout();
		gbl4.columnWidths = new int[] {150, 0, 0};
		gbl4.rowHeights = new int[]{15, 15, 0, 23, 0, 0};
		gbl4.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl4.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};

		stdoutPanel.setLayout(gbl4);
		
		
		GridBagConstraints gbc_stdoutPanelTitle = new GridBagConstraints();
		gbc_stdoutPanelTitle.gridwidth = 3;
		gbc_stdoutPanelTitle.insets = new Insets(0, 0, 5, 0);
		gbc_stdoutPanelTitle.gridx = 0;
		gbc_stdoutPanelTitle.gridy = 0;
		JLabel stdoutPaneTitle = new JLabel("Send events to stdout");
		stdoutPanel.add(stdoutPaneTitle, gbc_stdoutPanelTitle);
		
		stdoutEnableCheckbox = new JCheckBox("Enable");
		GridBagConstraints gbc_stdoutEnableCheckbox = new GridBagConstraints();
		gbc_stdoutEnableCheckbox.gridx = 2;
		gbc_stdoutEnableCheckbox.gridy = 4;
		stdoutPanel.add(stdoutEnableCheckbox, gbc_stdoutEnableCheckbox);
		
		
		//------------------ LogFile Panel ----------------------
		JPanel logfile_panel=new JPanel();
		addTab("File",logfile_panel);
		
		GridBagLayout gbl5 = new GridBagLayout();
		gbl5.columnWidths = new int[] {150, 0, 0};
		gbl5.rowHeights = new int[]{15, 15, 0, 23, 0, 0};
		gbl5.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl5.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};

		logfile_panel.setLayout(gbl5);
		
		
		GridBagConstraints gbc_logfilePaneTitle = new GridBagConstraints();
		gbc_logfilePaneTitle.insets = new Insets(0, 0, 5, 0);
		gbc_logfilePaneTitle.gridwidth = 2;
		gbc_logfilePaneTitle.gridx = 0;
		gbc_logfilePaneTitle.gridy = 0;
		JLabel logfilePaneTitle = new JLabel("Log events to file");
		logfile_panel.add(logfilePaneTitle, gbc_logfilePaneTitle);
		
		JLabel logfileLocationLabel = new JLabel("File Location");
		GridBagConstraints gbc_logfileLocationLabel = new GridBagConstraints();
		gbc_logfileLocationLabel.anchor = GridBagConstraints.EAST;
		gbc_logfileLocationLabel.insets = new Insets(0, 0, 5, 5);
		gbc_logfileLocationLabel.gridx = 0;
		gbc_logfileLocationLabel.gridy = 1;
		logfile_panel.add(logfileLocationLabel, gbc_logfileLocationLabel);
		
		logfileLocationTextField = new JTextField();
		logfileLocationTextField.setColumns(10);
		GridBagConstraints gbc_logfileLocationTextField = new GridBagConstraints();
		gbc_logfileLocationTextField.insets = new Insets(0, 0, 5, 0);
		gbc_logfileLocationTextField.fill = GridBagConstraints.HORIZONTAL;
		gbc_logfileLocationTextField.gridx = 1;
		gbc_logfileLocationTextField.gridy = 1;
		logfile_panel.add(logfileLocationTextField, gbc_logfileLocationTextField);
		
		logfileEnableCheckbox = new JCheckBox("Enable");
		GridBagConstraints gbc_logfileEnableCheckbox = new GridBagConstraints();
		gbc_logfileEnableCheckbox.anchor = GridBagConstraints.EAST;
		gbc_logfileEnableCheckbox.gridx = 1;
		gbc_logfileEnableCheckbox.gridy = 4;
		logfile_panel.add(logfileEnableCheckbox, gbc_logfileEnableCheckbox);

	}
}
