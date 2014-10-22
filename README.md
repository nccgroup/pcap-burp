This project provides a Burp Suite extension for importing Pcap files. It can be used in cases 
where a HTTP client does not support proxying but it would be useful to inspect or replay the HTTP traffic using Burp. 


Installation
------------

The Ant build file will produce a jar which can be added to Burp via Burp's "Extender" tab.
This project makes use of jpcap, which in turn relies on a native binary to be loaded by Java. 
You should download the correct binary from https://github.com/neonbunny/pcap-reconst/tree/master/lib 
and place it in your java.library.path (i.e. your %PATH% on Windows) 

Usage
-----

Once the extension has been loaded an "Open Pcap file..." option will be added to the "right-click" 
context menu on the trees under the Scanner and Target tabs in Burp. 

