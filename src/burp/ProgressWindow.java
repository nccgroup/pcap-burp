package burp;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Point;
import java.io.File;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;

public class ProgressWindow extends JDialog {
	private static final long serialVersionUID = 34345435L;
	
	private JProgressBar progressBar;
	private JLabel label;

	public ProgressWindow(JFrame parent, String title, String message) {
		super(parent, title, true);
		if (parent != null) {
			Dimension parentSize = parent.getSize();
			Point p = parent.getLocation();
			setLocation(p.x + parentSize.width / 4, p.y + parentSize.height / 4);
		}
		JPanel messagePane = new JPanel();
		label = new JLabel(message);
		messagePane.add(label);
		getContentPane().add(messagePane);

		JPanel progressPane = new JPanel();
		progressBar = new JProgressBar(0, 100);
		progressBar.setIndeterminate(true);
		progressBar.setPreferredSize(new Dimension(250, 20));
		progressBar.setVisible(true);
		progressPane.add(progressBar);

		getContentPane().add(progressPane, BorderLayout.SOUTH);
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
	}

	public void setCurrentFile(File file) {
		label.setText("Loading " + file.getName() + "...");
	}
}