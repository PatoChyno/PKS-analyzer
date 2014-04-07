package pack;

import java.awt.EventQueue;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.awt.event.InputEvent;
import java.io.File;

public class MainWindow {

	private JFrame frmNetPostanalyzer;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainWindow window = new MainWindow();
					window.frmNetPostanalyzer.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public MainWindow() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmNetPostanalyzer = new JFrame();
		frmNetPostanalyzer.setTitle("Net post-analyzer");
		frmNetPostanalyzer.setBounds(100, 100, 664, 434);
		frmNetPostanalyzer.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmNetPostanalyzer.getContentPane().setLayout(null);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(10, 11, 472, 333);
		frmNetPostanalyzer.getContentPane().add(scrollPane);
		
		final JTextArea textArea = new JTextArea();
		textArea.setFont(new Font("monospaced", Font.PLAIN, 14));
		scrollPane.setViewportView(textArea);
		
		final JLabel openFileLabel = new JLabel("(no file open)");
		openFileLabel.setBounds(10, 347, 428, 21);
		frmNetPostanalyzer.getContentPane().add(openFileLabel);
		
		JButton btnFrames = new JButton("All frames");
		btnFrames.setEnabled(false);
		btnFrames.setBounds(492, 10, 154, 23);
		frmNetPostanalyzer.getContentPane().add(btnFrames);
		JButton btnCommsNoConn = new JButton("TFTP");
		JButton btnCommsConn = new JButton("Telnet");
		class openDialogActionListener implements ActionListener {
			private File sf;
			private JFileChooser jfc;
			private JButton bf;
			private JButton bc1, bc2;
			
			public openDialogActionListener(JFileChooser jfc, JButton bf, JButton bc1, JButton bc2) {
				this.jfc = jfc;
				this.bc1 = bc1;
				this.bc2 = bc2;
				this.bf = bf;
			}
			public File getSelectedFile() {
			  return sf;
			}
			public void actionPerformed(ActionEvent e) {
				if (jfc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					sf = jfc.getSelectedFile();
					openFileLabel.setText("Open file: " + sf.getName());
					bf.setEnabled(true);
					bc1.setEnabled(true);
					bc2.setEnabled(true);
				}	
			}
		}
		JFileChooser fc = new JFileChooser();
		fc.setCurrentDirectory(new File("tests"));
		openDialogActionListener odal = new openDialogActionListener(fc, btnFrames, btnCommsNoConn, btnCommsConn);
		
		// --- class btnCommsNoConnActionListener ---
		
		class btnCommsNoConnActionListener implements ActionListener {
			openDialogActionListener al;
			public btnCommsNoConnActionListener(openDialogActionListener al) {
				this.al = al;
			}
			public void actionPerformed(ActionEvent e) {
				//openFileLabel.setText("Analyzing file: " + al.getSelectedFile().getName() + ", please wait...");
				CommsNoConn fileAnalyzer = new CommsNoConn();
				fileAnalyzer.analyze(al.getSelectedFile(), textArea);
				openFileLabel.setText("Analyzed file: " + al.getSelectedFile().getName());
			}
		}
		btnCommsNoConn.addActionListener(new btnCommsNoConnActionListener(odal));
		btnCommsNoConn.setEnabled(false);
		btnCommsNoConn.setVisible(false);
		btnCommsNoConn.setBounds(492, 44, 154, 21);
		frmNetPostanalyzer.getContentPane().add(btnCommsNoConn);

		// --- class btnCommsConnActionListener ---		
		
		class btnCommsConnActionListener implements ActionListener {
			openDialogActionListener al;
			public btnCommsConnActionListener(openDialogActionListener al) {
				this.al = al;
			}
			public void actionPerformed(ActionEvent e) {
				CommsConn fileAnalyzer = new CommsConn();
				fileAnalyzer.analyze(al.getSelectedFile(), textArea);
				openFileLabel.setText("Analyzed file: " + al.getSelectedFile().getName());
			}
		}
		
		btnCommsConn.addActionListener(new btnCommsConnActionListener(odal));
		btnCommsConn.setEnabled(false);
		btnCommsConn.setVisible(false);
		btnCommsConn.setBounds(492, 76, 154, 21);
		frmNetPostanalyzer.getContentPane().add(btnCommsConn);
				
		JMenuBar menuBar = new JMenuBar();
		frmNetPostanalyzer.setJMenuBar(menuBar);
		
		JMenu mnFile = new JMenu("File");
		menuBar.add(mnFile);
				
		JMenuItem mntmLoad = new JMenuItem("Open file...");
		mntmLoad.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_MASK));
		
		mntmLoad.addActionListener(odal);
		mnFile.add(mntmLoad);
		
		class btnFramesActionListener implements ActionListener {
			openDialogActionListener al;
			public btnFramesActionListener(openDialogActionListener al) {
				this.al = al;
			}
			public void actionPerformed(ActionEvent e) {
				PacketAnalysis fileAnalyzer = new PacketAnalysis();
				fileAnalyzer.analyze(al.getSelectedFile(), textArea);
			}
		}
		
		btnFramesActionListener bfal = new btnFramesActionListener(odal);
		btnFrames.addActionListener(bfal);
		JMenuItem mntmExit = new JMenuItem("Quit app");
		mntmExit.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_F4, InputEvent.ALT_MASK));
		mntmExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				System.exit(0);
			}
		});
		mnFile.add(mntmExit);
		
	}
}
