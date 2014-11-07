This project provides a Burp Suite extension for importing and passively scanning Pcap files with Burp. It can be used in cases 
where a HTTP client does not support proxying but it would be useful to scan, inspect or replay the HTTP traffic using Burp. 

Building from Source (optional)
-------------------------------
The Ant build file will produce a jar in the dist/lib directory.

Installation
------------
1. Use Burp's "Extender" tab to add the jar file from the dist/lib directory.
2. This project makes use of jpcap, which in turn relies on a native binary to be loaded by Java. 
Download the correct binary from https://github.com/neonbunny/pcap-reconst/tree/master/lib 
and place it in your java.library.path (i.e. your %PATH% on Windows) 

Usage
-----
After installation, an "Open Pcap file..." option will be added to the "right-click" 
context menu on the trees under the **Scanner** and **Target** tabs in Burp.

