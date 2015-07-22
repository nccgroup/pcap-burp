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
package com.nccgroup.burp.pcap;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.ex.PcapException;
import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.tcp.JnetpcapReconstructor;
import pcap.reconst.tcp.PacketReassembler;
import pcap.reconst.tcp.StatusHandle;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;
import burp.BurpExtender;

public class HttpReconstructor {

	private static Log log = LogFactory.getLog(HttpReconstructor.class);

	public static void loadPcap(File pcapFile, StatusHandle statusHandle) throws PcapException {
		try {
			// Reassemble the TCP streams.
			Map<TcpConnection, TcpReassembler> map = 
					new JnetpcapReconstructor(new PacketReassembler()).reconstruct(pcapFile.getAbsolutePath(), statusHandle);
			
			// Parse the HTTP flows from the streams.
			HttpFlowParser httpParser = new HttpFlowParser(map);
			Map<TcpConnection, List<RecordedHttpFlow>> flows = httpParser.parse(statusHandle);

			// Count the total number of extracted flows.
			int flowcount = 0;
			for (TcpConnection key : flows.keySet()) {
				flowcount += flows.get(key).size();
			}
			BurpExtender.callbacks.printOutput("Parsed " + flowcount + " total flows.");
		}
		catch (PcapException pce)
		{
			//These can propagate up the stack - all other exceptions are squashed below
			throw pce;
		}
		catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error("", e);
			}
		}
	}
}
