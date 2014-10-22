package com.nccgroup.burp.pcap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;

import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.UncompressImpl;
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
			rawdata = assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd);
			
			PcapRequestResponse rr = new PcapRequestResponse(flow, assembler);
			BurpExtender.callbacks.addToSiteMap(rr);
			IHttpService rrServ = rr.getHttpService();
			BurpExtender.callbacks.doPassiveScan(rrServ.getHost(), rrServ.getPort(), false, rr.getRequest(), rr.getResponse());
			
			RecordedHttpRequestMessage request;
			RecordedHttpResponse response = null;

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
			super(stripChunkedEncoding(assembler.getOrderedPacketDataBytes(flow.reqStart, flow.reqEnd)),
					decompressIfRequired(stripChunkedEncoding(assembler.getOrderedPacketDataBytes(flow.respStart, flow.respEnd))));
			
			this.flow = flow;
			this.assembler = assembler;
		}
		
		/**
		 * Decompresses the body of applicable HTTP streams.
		 * 
		 * @param input A byte array representing one side of the HTTP conversation.
		 * @return The input without the body ungzipped, or the original input if 
		 * it's not a well formed gzip stream.
		 */
		public static byte[] decompressIfRequired(byte[] input)
		{
			final int MAX_HEADER_SIZE = 16 * 1024;
			final String HEADER_BODY_SEPERATOR = "\r\n\r\n";
			
			String initialPart = new String(input, 0, Math.min(MAX_HEADER_SIZE, input.length));
			int headerLocation = initialPart.indexOf("Content-Encoding: gzip\r\n");
			if (headerLocation >= 0)
			{
				int bodyOffset = initialPart.indexOf(HEADER_BODY_SEPERATOR) + HEADER_BODY_SEPERATOR.length();
				if(headerLocation >= bodyOffset)
				{
					//The header that we found was actually in the body - so it's not gzip'ed after all
					return input;
				}
				
				ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length);
				//Output the header verbatim
				baos.write(input, 0, bodyOffset);
				
				try {
					baos.write(new UncompressImpl(CompressionType.gzip, Arrays.copyOfRange(input, bodyOffset, input.length), null).uncompress());
					return baos.toByteArray();
				} catch (IOException e1) {
					BurpExtender.callbacks.printError("Unable to ungzip - returning raw data");
					return input;
				}
			}
			
			return input;
		}
			
		
		/**
		 * Removes the chunked encoding parts from applicable HTTP streams.
		 * 
		 * @param input A byte array representing one side of the HTTP conversation.
		 * @return The input without the additional chunked encoding parts littering
		 * the body, or the original input if it's not a well formed chunked encoded HTTP stream.
		 */
		public static byte[] stripChunkedEncoding(byte[] input)
		{
			final int MAX_HEADER_SIZE = 16 * 1024;
			final String HEADER_BODY_SEPERATOR = "\r\n\r\n";
			
			String initialPart = new String(input, 0, Math.min(MAX_HEADER_SIZE, input.length));
			int headerLocation = initialPart.indexOf("Transfer-Encoding: chunked\r\n");
			if (headerLocation >= 0)
			{
				int bodyOffset = initialPart.indexOf(HEADER_BODY_SEPERATOR) + HEADER_BODY_SEPERATOR.length();
				if(headerLocation >= bodyOffset)
				{
					//The header that we found was actually in the body - so it's not chunk encoded after all
					return input;
				}
				
				ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length);
				//Output the header verbatim
				baos.write(input, 0, bodyOffset);
				
				//Create a temp buffer for the remainder
				ByteArrayInputStream bais = new ByteArrayInputStream(input, bodyOffset, input.length - bodyOffset);
				byte nextByte = 0;
				
				//Until we've processed all of the input
				while(nextByte != -1)
				{	
					StringBuffer hexBuffer = new StringBuffer();
					
					//Stop parsing the length bytes when we hit a non-hex char
					while(nextByte != (byte)'\r' && nextByte != (byte)';')
					{
						nextByte = (byte) bais.read();
						hexBuffer.append((char)nextByte);
					}
					//Consume up to the \n
					while(nextByte != (byte)'\n' )
					{
						nextByte = (byte) bais.read();
					}
					
					//Trim the last character now we've established it's not hex
					hexBuffer.setLength(hexBuffer.length() - 1);
					int chunkSize = Integer.parseInt(hexBuffer.toString(), 16);
					if (chunkSize == 0)
					{
						//There may be some trialers at this point - but we've nowhere to put them, so drop them
						return baos.toByteArray();
					}

					try {
						byte[] nextChunk = new byte[chunkSize];
						bais.read(nextChunk);
						baos.write(nextChunk);
					} catch (IOException e) {
						BurpExtender.callbacks.printError("Unable to copy between streams.");
						e.printStackTrace(System.err);
					}
					
					if (bais.read() != (byte)'\r' || bais.read() != (byte)'\n')
					{
						BurpExtender.callbacks.printError("Unexpected end to chunk - returning raw data");
						return input;
					}
				}
				
				//We should have hit the zero chunk and returned by now - something's gone wrong, so just return the original.
				BurpExtender.callbacks.printError("Incomplete chunked encoding - returning raw data");
				return input;
			}
			else
			{
				return input;
			}
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
