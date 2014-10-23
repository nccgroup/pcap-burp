package com.nccgroup.burp.pcap;

import java.io.File;

import javax.swing.filechooser.FileFilter;

public class PcapFileFilter extends FileFilter {
	@Override
	public String getDescription() {
		return "*.pcap files";
	}

	@Override
	public boolean accept(File f) {
		return f.isDirectory() || f.getName().endsWith(".pcap");
	}
}