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

import javax.swing.filechooser.FileFilter;

public class PcapFileFilter extends FileFilter {
	@Override
	public String getDescription() {
		return "Packet Capture Files (*.pcap;*.pcapng files)";
	}

	@Override
	public boolean accept(File f) {
		return f.isDirectory() || f.getName().endsWith(".pcap") || f.getName().endsWith(".pcapng");
	}
}