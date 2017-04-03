This project provides a Burp Suite extension for importing and passively scanning Pcap/Pcapng files with Burp. It can be used in cases 
where a HTTP client does not support proxying but it would be useful to scan, inspect or replay the HTTP traffic using Burp. 

Building from Source (optional)
-------------------------------
The Ant "dist" target will produce a consolidated jar in the dist/lib directory.

Installation
------------
Use Burp's "Extender" tab to add the latest jar file from the [dist/lib](https://github.com/nccgroup/pcap-burp/tree/master/dist/lib) directory.

Usage
-----
After installation, an "Open Pcap file..." option will be added to the "right-click" 
context menu on the **Scanner Issues**, **Target Tree** and **Request/Response View** areas of Burp.