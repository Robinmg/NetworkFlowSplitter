# Traffic Flow Splitter

This is an older project from a Networks class.
This program takes in a .pcap file containing inboud/outbound packets on a network,
then pairs all of the packets based on source and destination IPs. These are split into two types
of flows:
* Single Flows:
.. These are flows which only travelled in one direction
* Flow Pairs
.. Flows in which there were multiple packets to and from a specific IP

The program splits each of these flows into their own seperate pcap files for later analysis
