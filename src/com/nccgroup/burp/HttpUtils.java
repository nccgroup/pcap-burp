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
package com.nccgroup.burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.UncompressImpl;
import burp.BurpExtender;

public class HttpUtils {
	/** Maximum amount of data at the begining of a stream to parse as headers. They can be very large if they include ASP ViewStates */
	private static final int MAX_HEADER_SIZE = 32 * 1024;
	
	/** RegEx for the continue block */
	private static final Pattern CONTINUE_PATTERN = Pattern.compile("(?s)HTTP\\/1\\.1 100 Continue(.*?)\\r\\n\\r\\n");
	
	/**
	 * Removes provisional "HTTP/1.1 100 Continue" server responses from the request stream. 
	 * These responses will appear in the request stream (rather than the response stream) given 
	 * the assumption from the HTTP splitting library that a HTTP conversion contains a single 
	 * request followed by a single response.
	 *  
	 * @return The given byte[] without a provisional response embedded within.
	 */
	public static byte[] stripContinueFromRequests(byte[] input)
	{
		byte[] result = input;

		//Loop until we fail to find any more
		while (true)
		{
			String initialPart = new String(result, 0, Math.min(MAX_HEADER_SIZE, result.length));
		    Matcher m = CONTINUE_PATTERN.matcher(initialPart);
			
		    if (m.find())
		    {
				int stringIndex = m.start();
				final int stringLength = m.end() - m.start();
	
				result = new byte[input.length - stringLength];
				//Copy up to the string we wish to exclude
				System.arraycopy(input, 0, result, 0, stringIndex);
				//Copy the other side of the byte array after the string we wish to exclude
				System.arraycopy(input, stringIndex + stringLength, result, stringIndex, input.length - (stringIndex + stringLength));
		    }
			else
			{
				//No more to find - time to return
				break;
			}
		}
		return result;
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
		final String HEADER_BODY_SEPERATOR = "\r\n\r\n";
		
		String initialPart = new String(input, 0, Math.min(MAX_HEADER_SIZE, input.length));
		int headerLocation = initialPart.toLowerCase().indexOf("transfer-encoding: chunked\r\n");
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
				StringBuffer hexBuffer = new StringBuffer(100);
				
				//Stop parsing the length bytes when we hit a non-hex char
				while(nextByte != (byte)'\r' && nextByte != (byte)';')
				{
					nextByte = (byte) bais.read();
					hexBuffer.append((char)nextByte);
					if(hexBuffer.length() > 99)
					{
						//We shouldn't be dealing with this much hex - something is wrong
						return input;
					}
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
					//There may be some trailers at this point - but we've nowhere to put them, so drop them
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

}
