package com.nccgroup.burp.pcap;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import burp.BurpExtender;
import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.tcp.JpcapReconstructor;
import pcap.reconst.tcp.PacketReassembler;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;

public class HttpReconstructor {

	private static Log log = LogFactory.getLog(HttpReconstructor.class);

	public static void loadPcap(File pcapFile) {
		try {
			// Reassemble the TCP streams.
			Map<TcpConnection, TcpReassembler> map = 
					new JpcapReconstructor(new PacketReassembler()).reconstruct(pcapFile.getAbsolutePath());

			// Parse the HTTP flows from the streams.
			HttpFlowParser httpParser = new HttpFlowParser(map);
			Map<TcpConnection, List<RecordedHttpFlow>> flows = httpParser.parse();

			// Count the total number of extracted flows.
			int flowcount = 0;
			for (TcpConnection key : flows.keySet()) {
				flowcount += flows.get(key).size();
			}
			BurpExtender.callbacks.printOutput("Parsed " + flowcount + " total flows.");
		} catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error("", e);
			}
		}
	}
}
