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
import java.util.Collections;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import pcap.reconst.ex.PcapException;

import com.nccgroup.burp.pcap.HttpReconstructor;
import com.nccgroup.burp.pcap.PcapFileFilter;

public class BurpExtender implements IBurpExtender
{
	public static IBurpExtenderCallbacks callbacks;

	private static final class OpenPcapFileMenuAction extends AbstractAction {
		/**
		 * Generate by Eclipse
		 */
		private static final long serialVersionUID = 5003331249971440291L;
		
		//Create a file chooser
		private final JFileChooser fc = new JFileChooser();

		public OpenPcapFileMenuAction() {
			fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
			fc.setFileFilter(new PcapFileFilter());
			
			setEnabled(true);
			putValue("Name", "Open Pcap File...");
		}
		
		public void actionPerformed(ActionEvent e) {
			int returnVal = fc.showOpenDialog(null);

		    if (returnVal == JFileChooser.APPROVE_OPTION) {
		        File file = fc.getSelectedFile();
		        try
		        {
		        	HttpReconstructor.loadPcap(file);
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
		    }
		}
	}

    
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	BurpExtender.callbacks = callbacks;
    	
    	callbacks.registerContextMenuFactory(new IContextMenuFactory() {
			
			public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
				if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE ||
						invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS)
				{
					return Collections.singletonList(new JMenuItem(new OpenPcapFileMenuAction()));
				}
				else
				{
					return Collections.emptyList();
				}
			}
		});
    	
        // set our extension name
        callbacks.setExtensionName("Pcap File Parser");
    }
}