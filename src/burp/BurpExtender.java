/* 
 * Released as open source by NCC Group Plc - https://www.nccgroup.com/
 *
 * Developed by Stephen Tomkinson, stephen.tomkinson@nccgroup.com
 * 
 * https://www.github.com/nccgroup/pcap-burp
 *
 * Licensed under the Affero General Public License 
 * https://github.com/nccgroup/pcap-burp/LICENSE
 */
package burp;

import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import pcap.reconst.ex.PcapException;
import pcap.reconst.tcp.StatusHandle;

import com.nccgroup.burp.pcap.HttpReconstructor;
import com.nccgroup.burp.pcap.PcapFileFilter;
import com.nccgroup.burp.pcap.PcapngToPcap;

public class BurpExtender implements IBurpExtender
{
	public static IBurpExtenderCallbacks callbacks;

	private static final class OpenPcapFileMenuAction extends AbstractAction {
		/** The config name for the previously accessed Pcap directory **/
		private static final String PREV_PCAP_DIR = "PREV_PCAP_DIR";

		/**
		 * Generate by Eclipse
		 */
		private static final long serialVersionUID = 5003331249971440291L;
		
		//Create a file chooser
		private final JFileChooser fc = new JFileChooser();

		public OpenPcapFileMenuAction() {
			fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
			fc.setMultiSelectionEnabled(true);
			fc.setFileFilter(new PcapFileFilter());
			
			String previousDir = BurpExtender.callbacks.loadExtensionSetting(PREV_PCAP_DIR);
			if (previousDir != null)
			{
				File previousDirFileObj = new File(previousDir);
				//The FileChooser will gracefully handle non-existent directories
				fc.setCurrentDirectory(previousDirFileObj);
			}
			
			setEnabled(true);
			putValue("Name", "Open Pcap File...");
		}
		
		public void actionPerformed(ActionEvent e) {	        
			int returnVal = fc.showOpenDialog(null);
			
		    if (returnVal == JFileChooser.APPROVE_OPTION) {
				//GUI wont refresh until this method returns, so kick off a new thread
		    	new Thread(new Runnable() {
					public void run() {
				        File[] files = fc.getSelectedFiles();

						final ProgressWindow progressWindow = new ProgressWindow(
								new JFrame(), "Open Pcap File...", "Preparing...");

						final StatusHandle statusHandle = new StatusHandle();
						
						//New thread for the modal dialog, as setVisible is blocking
						new Thread(new Runnable() {
							public void run() {
								progressWindow.setLocationRelativeTo(null);
								progressWindow.setVisible(true);
								statusHandle.cancel();
							}}).start();

			        	for (File file : files)
			        	{
			        		boolean shouldDelete = false;
			        		BurpExtender.callbacks.saveExtensionSetting(PREV_PCAP_DIR, file.getParent());

			        		progressWindow.setCurrentFile(file);
			        		
			        		if (file.getAbsolutePath().endsWith(".pcapng"))
			        		{
			        			try
			        			{
				        			File tempFile = File.createTempFile("burp", ".pcap");
				        			PcapngToPcap.convert(file, tempFile);
				        			file = tempFile;
				        			shouldDelete = true;
			        			}
			        			catch (IOException ioe)
			        			{
			        				JOptionPane.showMessageDialog(null,
						        		    ioe.getLocalizedMessage(),
						        		    "Pcapng Conversion Exception",
						        		    JOptionPane.ERROR_MESSAGE);
			        				break;
			        			}
			        		}
			        		
			        		
							try {
								HttpReconstructor.loadPcap(file, statusHandle);
							}
					        catch(PcapException pce)
					        {
					        	JOptionPane.showMessageDialog(null,
					        		    pce.getLocalizedMessage(),
					        		    "Pcap Exception",
					        		    JOptionPane.ERROR_MESSAGE);
					        }
					        catch(UnsatisfiedLinkError ule)
					        {
					            // write a message to the Burp alerts tab
					            callbacks.issueAlert("Unable to load jNetPcap library from java.library.path");
			            		callbacks.issueAlert("java.library.path is "+ System.getProperty("java.library.path"));
			            		callbacks.issueAlert("Visit https://github.com/neonbunny/pcap-reconst/tree/master/lib for available libraries.");
					        }
							finally
							{
								if (shouldDelete)
								{
									file.delete();
								}
							}
						}
			        	
			        	progressWindow.dispose();					
		        	}}).start();
			}
		}
	}

    
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	BurpExtender.callbacks = callbacks;
    	
    	callbacks.registerContextMenuFactory(new IContextMenuFactory() {
			
			public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
				switch (invocation.getInvocationContext())
				{
					case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
					case IContextMenuInvocation.CONTEXT_SCANNER_RESULTS:
					case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
					case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
					case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
						return Collections.singletonList(new JMenuItem(new OpenPcapFileMenuAction()));
					default:
						return Collections.emptyList();
				}
			}
		});
    	
        // set our extension name
        callbacks.setExtensionName("Pcap File Parser");
    }
}