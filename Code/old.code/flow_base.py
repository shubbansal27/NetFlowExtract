from scapy.all import *
import pickle
import os 


####################### Function: extractFlows() ##########################
'''
@Parameter 1: packetList object
@Parameter 2: output pickleFile path, this is optional parameter. If valid path exists then function will return flowList by de-serialising the pickle file data

return: function return the flowList which a list of list
'''
def extractFlows(packets, outputPickleFile=None):

	if outputPickleFile != None and  os.path.exists(outputPickleFile):
		fp = open( 'flows.pik', "rb" )	
		flowList = pickle.load(fp)	
		fp.close()
		return flowList

	num = 0
	flowList = []

	for pk in packets:
		if pk.haslayer(IP) and pk.haslayer(TCP):
			src = pk['IP'].src
			dst = pk['IP'].dst
			sport = pk['IP'].sport
			dport = pk['IP'].dport	
				
			#rules
			#filter protocol, remove ack, threshold on minimum packets, 	


			if len(flowList) == 0:
				flowList.append([[src,dst],[sport,dport],[num]])
			else:
				flag = False
				for flow in flowList:
					if src in flow[0] and dst in flow[0] and sport in flow[1] and dport in flow[1]:
						flow[2].append(num)
						flag = True
						break	
				if not flag:
					flowList.append([[src,dst],[sport,dport],[num]])
		
		num += 1


	#writing flowList into pickle 
	if outputPickleFile != None: 
		fout = open(outputPickleFile, "wb" ) 
		pickle.dump(flowList, fout )
		fout.close()

	return flowList




############################################ function: extractFeatures() #######################

def extractFeatures(packets, flow):

	featureVector = []
	featureVector.append(len(flow[2]))   			 #feature-1  total count of packets 

	totalLength = 0
	numPackets = len(flow[2])
	for pktNumber in flow[2]:
		totalLength += packets[pktNumber][IP].len	
	avgLength = float(totalLength)/numPackets
	featureVector.append(avgLength)       			 #feature-2  Average length of packets

	return featureVector

################


################

#######################  main code ################################

#read pcap file
print 'parsing pacap started...'
packets = rdpcap('filtered.pcap.pcapng')
print 'parsing complete...'

#extract flow
flowList = extractFlows(packets,'flows.pik')       
print flowList
print 'Total packets = ', len(packets)
print 'Total no flows = ', len(flowList)

#extract features
#total packet count, avg packet size in byte
row = 1
for flow in flowList:
	featureRow = extractFeatures(packets,flow) 
	#print row, featureRow
	row += 1








	
