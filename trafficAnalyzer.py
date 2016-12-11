import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#don't display low-priority warnings
from scapy.all import * #pcap analysis library

flows = []#holds the source an destination IP of each flow
flowData = []#holds the packets of each flow
flowPairs = []#holds tuples which identify which sets of flowData are pairs
flowSingles = []#holds flows which only go one way
totalPackets = 0
totalFlows = 0
packetsPerFlow = []

#splits the flows into their respective pairs (each flow has an inbound and outbound file)
def createFlowPairs(ip_tuples):
	for indexOne, tuple in enumerate(ip_tuples):
		currentFlowNum = len(flowPairs)
		for indexTwo, tupleTwo in enumerate(ip_tuples[indexOne:]):
			if (tuple[0] == tupleTwo[1]) & (tuple[1] == tupleTwo[0]):
				flowPairs.append((indexOne, indexTwo))
		if len(flowPairs) == currentFlowNum:
			flowSingles.append(indexOne)
			
		
#returns the index of a flow that the source and destination IP tuple identifies
def whichFlow(src, dst):
	for index, flow in enumerate(flows):
		if flow == (src, dst):
			return index
	flows.append((src, dst))
	flowData.append([])
	return len(flows) - 1	



#get filename, then open and grab relevent data
captureFile = raw_input("Enter a .pcap file for analysis: ")
packets = rdpcap(captureFile)#rdpcap = scapy tool for parsing pcap files
totalPackets = len(packets)

#iterate through each packet in the capture file
for pkt in packets:
	if IP in pkt:#if packet contains IP data
		ip_src = pkt[IP].src#parse source IP
		ip_dst = pkt[IP].dst#parse destination IP
		flowNum = whichFlow(ip_src, ip_dst)#find which flow the IPs identify with
		flowData[flowNum].extend(pkt)#add the packet to its respective flow

#pair up the inbound and outbound packets of a flow for easy file names
createFlowPairs(flows)
totalFlows = len(flowPairs) + len(flowSingles)

i=0#for file organizing
#iterate through every flow and write to file
for flow in flowPairs:	
	wrpcap('flow'+str(i)+'sent.pcap', flowData[flow[0]])#sent flow
	wrpcap('flow'+str(i)+'received.pcap', flowData[flow[1]])#received flow
	packetsPerFlow.append('Flow #'+str(i)+' Packet Count:  '+str(len(flowData[flow[0]]) + len(flowData[flow[1]])))#update packets per flow
	i = i + 1
for flow in flowSingles:
	wrpcap('flow'+str(i)+'.pcap', flowData[flow])
	i = i+1
	packetsPerFlow.append('Flow #'+str(i)+' Packet Count:  '+str(len(flowData[flow])))
#open file for flow stats
statFile = open('flow.pcap.stats', 'a+')

statFile.write("Total Packets: " + str(totalPackets))
statFile.write("\nTotal Flows: " + str(totalFlows))

for entry in packetsPerFlow:
	statFile.write("\n"+entry)
statFile.write("\n")
statFile.close()

print "You may veiw basic flow statistics in the generated file: <flow.pcap.stats>"
