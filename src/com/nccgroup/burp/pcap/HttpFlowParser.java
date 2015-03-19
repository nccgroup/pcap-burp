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

import java.io.IOException;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;

import com.nccgroup.burp.HttpUtils;
import com.nccgroup.burp.IHttpRequestResponseImpl;

import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.http.datamodel.RecordedHttpRequestMessage;
import pcap.reconst.http.datamodel.RecordedHttpResponse;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;
import burp.BurpExtender;
import burp.IHttpService;
import burp.IRequestInfo;

public class HttpFlowParser extends pcap.reconst.http.HttpFlowParser {

	private static Log log = LogFactory.getLog(HttpFlowParser.class);

	public HttpFlowParser(Map<TcpConnection, TcpReassembler> map) {
		super(map);
	}

	@Override
	protected RecordedHttpFlow toHttp(final FlowBuf flow, final TcpReassembler assembler) throws IOException, HttpException {
		if (log.isDebugEnabled()) {
			log.debug("Processing flow " + flow);
		}
		byte[] rawdata = null;
		if (flow.hasRequestData()) {
			PcapRequestResponse rr = new PcapRequestResponse(flow, assembler);
			BurpExtender.callbacks.addToSiteMap(rr);
			IHttpService rrServ = rr.getHttpService();
			BurpExtender.callbacks.doPassiveScan(rrServ.getHost(), rrServ.getPort(), false, rr.getRequest(), rr.getResponse());
			
			RecordedHttpRequestMessage request;
			RecordedHttpResponse response = null;

			rawdata = assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd);
			
			if (flow.hadResponseData()) {
				byte[] respBytes = assembler.getOrderedPacketDataBytes(flow.respStart, flow.respEnd);
				byte[] reqRespbytes = new byte[rawdata.length + respBytes.length];
				System.arraycopy(rawdata, 0, reqRespbytes, 0, rawdata.length);
				System.arraycopy(respBytes, 0, reqRespbytes, rawdata.length, respBytes.length);
				rawdata = reqRespbytes;
				request = getRequest(flow, assembler);
				response = getResponse(flow, assembler);
			} else {
				request = getRequest(flow, assembler);
			}
			
			BurpExtender.callbacks.printOutput("Parsed " + request.getUrl());
			return new RecordedHttpFlow(rawdata, request, response);
		}
		return null;
	}

	
	private static final class PcapRequestResponse extends IHttpRequestResponseImpl {
		private final FlowBuf flow;
		private final TcpReassembler assembler;
		private IHttpService httpService;

		private PcapRequestResponse(FlowBuf flow, TcpReassembler assembler) 
		{
			super(HttpUtils.stripChunkedEncoding(HttpUtils.stripContinueFromRequests(assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd))),
					flow.respStart == -1 ? new byte[0] : HttpUtils.decompressIfRequired(HttpUtils.stripChunkedEncoding(assembler.getOrderedPacketDataBytes(flow.respStart, flow.respEnd))));
			
			this.flow = flow;
			this.assembler = assembler;
		}
		
		@Override
		public synchronized IHttpService getHttpService() {
			if (httpService == null)
			{
				IRequestInfo req = BurpExtender.callbacks.getHelpers().analyzeRequest(getRequest());	
				
				String host = null;
				for (String header : req.getHeaders())
				{
					if(header.startsWith("Host: "))
					{
						host = header.substring("Host: ".length());
						if (host.contains(":"))
						{
							String[] parts = host.split(":", 2);
							if (parts.length == 2)
							{
								//We've got the host & port from the "Host: " header
								httpService = BurpExtender.callbacks.getHelpers().buildHttpService(
										parts[0],
										Integer.valueOf(parts[1]),
										false);
								return httpService;
							}
						}
						else
						{
							//We've only got the host from the "Host: " header, extract the port from the TCP connection
							httpService = BurpExtender.callbacks.getHelpers().buildHttpService(
									host,
									assembler.getTcpConnection(flow.reqStart, flow.reqEnd).getDstPort(),
									false);
							return httpService;
						}
					}
				}
				
				//Host header parsing failed - extract from the TCP connection.
				httpService = BurpExtender.callbacks.getHelpers().buildHttpService(
						assembler.getTcpConnection(flow.reqStart, flow.reqEnd).getDstIp().getHostName(),
						assembler.getTcpConnection(flow.reqStart, flow.reqEnd).getDstPort(),					
						false);
			}
			
			return httpService;
		}
	}

}
