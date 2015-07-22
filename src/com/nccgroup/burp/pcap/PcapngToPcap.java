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
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;

import fr.bmartel.pcapdecoder.PcapDecoder;
import fr.bmartel.pcapdecoder.constant.LinkLayerConstants;
import fr.bmartel.pcapdecoder.structure.options.inter.IOptionsDescriptionHeader;
import fr.bmartel.pcapdecoder.structure.types.IPcapngType;
import fr.bmartel.pcapdecoder.structure.types.inter.IDescriptionBlock;
import fr.bmartel.pcapdecoder.structure.types.inter.IEnhancedPacketBLock;
import fr.bmartel.pcapdecoder.utils.DecoderStatus;

public class PcapngToPcap {

	private static final byte[] MAGIC_NUMBER = {(byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1};
	private static final byte[] VERSION = {0x02, 0x00, 0x04, 0x00};
	private static final byte[] TIMEZONE_OFFSET = {0x00, 0x00, 0x00, 0x00};
	private static final byte[] TIMING_ACCURACY = {0x00, 0x00, 0x00, 0x00};
	private static final byte[] BLANK_TIMESTAMP = new byte[] {0, 0, 0, 0, 0, 0, 0, 0};
	
	public static void main(String[] args) throws IOException 
	{
		long startTime = System.currentTimeMillis();
		
		convert(new File(args[0]), new File(args[1]));
		
		long endTime = System.currentTimeMillis();
		long totalTime = endTime - startTime;
		System.out.println("Conversion time : " + totalTime + " millis");
	}

	/**
	 * Converts the given PCAPNG formatted file into the older PCAP format out writes the result to the given file.
	 * 
	 * @param pcapngInFile An existing PCAPNG formatted file.
	 * @param pcapOutFile Where to write the PCAP formatted file to.
	 * @throws IOException If unable to convert.
	 */
	public static void convert(File pcapngInFile, File pcapOutFile) throws IOException
	{
		byte[] inputBytes = Files.readAllBytes(pcapngInFile.toPath());
		
		if (inputBytes[0] != 0x0A || inputBytes[1] != 0x0D || inputBytes[2] != 0x0D || inputBytes[3] != 0x0A)
		{
			throw new IOException("Pcapng file missing expected header");
		}
		
		PcapDecoder pcapNgDecoder = new PcapDecoder(inputBytes);
		int status = pcapNgDecoder.decode();
		
		if (status==DecoderStatus.SUCCESS_STATUS)
		{
			FileOutputStream fos = new FileOutputStream(pcapOutFile);
			try
			{
				//PCAP header constants
				fos.write(MAGIC_NUMBER);
				fos.write(VERSION);
				fos.write(TIMEZONE_OFFSET);
				fos.write(TIMING_ACCURACY);
				convert(pcapNgDecoder, fos);
			}
			finally
			{
				fos.close();
			}
		}
		else
		{
			throw new IOException("Unable to parse pcapng file");
		}
	}
	
	
	/** 
	 * Extracts the required parts from the decoded pcapng file and writes them in the same order to the pcap output stream.
	 * 
	 * @param decoder The decoded pcapng file.
	 * @param fos An output stream to write the PCAP content to.
	 * @throws IOException If unable to create a valid PCAP file.
	 */
	private static void convert(PcapDecoder decoder, FileOutputStream fos) throws IOException
	{
		boolean headerWritten = false;
		TimeUnit timeunit = null;
		
		for (IPcapngType section : decoder.getSectionList())
		{
			if (section instanceof IDescriptionBlock && !headerWritten)
			{
				timeunit = convertDescriptionBlock(fos, (IDescriptionBlock) section);
				headerWritten = true;
			}
			else if (section instanceof IEnhancedPacketBLock)
			{
				convertPacket(fos, timeunit, (IEnhancedPacketBLock) section);
			}
		}
	}

	private static TimeUnit convertDescriptionBlock(FileOutputStream fos,
			IDescriptionBlock descriptionBlock) throws IOException 
	{
		ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
		
		//SnapLen
		if (descriptionBlock.getSnapLen()!=-1)
		{
			bb.clear();
			bb.putInt(descriptionBlock.getSnapLen());
			fos.write(bb.array());
		}
		else
		{
			throw new IOException("Unable to determine Snap Length.");
		}
		
		//Link Layer
		if (!descriptionBlock.getLinkType().equals(""))
		{
			for (int k : LinkLayerConstants.LINK_LAYER_LIST.keySet())
			{
				if(LinkLayerConstants.LINK_LAYER_LIST.get(k).toString() == descriptionBlock.getLinkType())
				{
					bb.clear();
					bb.putInt(k);
					fos.write(bb.array());
				}
			}
		}
		else
		{
			throw new IOException("Unable to determine Link Layer type.");
		}
		
		//Store timestamp precision for per packet calculations
		IOptionsDescriptionHeader optionsList = descriptionBlock.getOptions();
		
		if (optionsList!=null)
		{
			if (optionsList.getTimeStampResolution()!=-1)
			{
				switch (optionsList.getTimeStampResolution())
				{
					case 0:
						return TimeUnit.SECONDS;
					case 3:
						return TimeUnit.MILLISECONDS;
					case 6:
						return TimeUnit.MICROSECONDS;
					case 9:
						return TimeUnit.NANOSECONDS;
					default:
						throw new IOException("Unexpected timestamp resolution: " + optionsList.getTimeStampResolution());
				}
			}
			else
			{
				throw new IOException("No Timestamp Resolution in Description Block");
			}
		}
		else
		{
			throw new IOException("No Options List in Description Block");
		}
	}

	private static void convertPacket(FileOutputStream fos,
			TimeUnit timeunit, IEnhancedPacketBLock temp) throws IOException 
	{
		ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
		
		if (temp.getTimeStamp()!=-1)
		{					
			//Seconds
			int seconds = (int)timeunit.toSeconds(temp.getTimeStamp());
			bb.clear();
			bb.putInt(seconds);
			fos.write(bb.array());
			
			//Micros
			int micros = (int)(timeunit.toMicros(temp.getTimeStamp()) % 1000000L);
			bb.clear();
			bb.putInt(micros);
			fos.write(bb.array());
		}
		else
		{
			//Blank timestamp
			fos.write(BLANK_TIMESTAMP);
		}
			
		//Packet length
		bb.clear();
		bb.putInt(temp.getPacketLength());
		fos.write(bb.array());
		
		//Captured length
		bb.clear();
		bb.putInt(temp.getCapturedLength());
		fos.write(bb.array());
	
		//Packet data
		fos.write(temp.getPacketData());
	}
}
