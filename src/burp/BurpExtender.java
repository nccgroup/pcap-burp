package burp;

import java.awt.event.ActionEvent;
import java.io.File;
import java.util.Collections;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;

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
		        catch(UnsatisfiedLinkError ule)
		        {
		            // write a message to the Burp alerts tab
		            callbacks.issueAlert("Unable to load jpcap library from java.library.path");
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
        
        /*
        // obtain our output and error streams
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // write a message to our output stream

        stdout.println("Hello output");
        stdout.println(System.getProperty("java.library.path"));
        
        // write a message to our error stream
        stderr.println("Hello errors");
        
        // write a message to the Burp alerts tab
        callbacks.issueAlert("Hello alerts");
        
        // throw an exception that will appear in our error stream
        //throw new RuntimeException("Hello exceptions");
        */
        //HttpReconstructorExample.main(new String[] {"C:/Users/stephen/Desktop/dlna-bounce/bluray-2014-registration.pcap"});
        //HttpReconstructorExample.main(new String[] {"C:/Users/stephen/Downloads/4od-cap.pcap"});
    }
}