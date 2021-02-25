from scapy.all import *
import pickle
import os 


####################### Function: extractFlows() ##########################
'''
@Parameter 1: packetList object
@Parameter 2: output pickleFile path, this is optional parameter. If valid path exists then function will return flowList by de-serialising the pickle file data

return: flowList which is list of list object..  ==> [ [srcIP, dstIP], [srcPort, dstPort], [packetIndex1, packetIndex2,........]]
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
			#Ex: filter protocol, remove ack, threshold on minimum packets, 	


			#aggregating packets into flow			
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

'''
@Parameter 1: packetList object
@Parameter 2: flowList which is list of list object..  ==> [ [srcIP, dstIP], [srcPort, dstPort], [packetIndex1, packetIndex2,........]]

return: function return the feature vector which is list of numeric values
'''

def extractFeatures(packets, flow):

	#creating featureVector list
	featureVector = []

	#Adding features to feature vector

	#1
	totalPacketCount = feature_TotalPackets(packets, flow)
	featureVector.append(totalPacketCount)   			

	#2
	avgPacketSize = feature_AveragePacketSize(packets, flow)	
	featureVector.append(avgPacketSize)   			

	return featureVector


############################################ functions for features #######################

 
def feature_TotalPackets(packets, flow):
	return len(flow[2])	



def feature_AveragePacketSize(packets, flow):  
	totalLength = 0
	numPackets = len(flow[2])
	for pktNumber in flow[2]:
		totalLength += packets[pktNumber][IP].len	
	avgLength = float(totalLength)/numPackets
	return avgLength

       			 


#######################  main code ################################

#variables
application = 'faceboook'
pcapFilePath = 'filtered.pcap.pcapng'
flowPicklePath = 'flows.pik'   # this is optional parameter..   if not required then set it to None [ ex: flowPicklePath = None ]
outputPathCSV = 'out_features.csv'


#reading pcap file
print 'parsing pcap started...'
packets = rdpcap(pcapFilePath)
print 'parsing complete...'

#extracting flow
flowList = extractFlows(packets,flowPicklePath)       
#print flowList
print 'Total packets = ', len(packets)
print 'Total no flows = ', len(flowList)


#extracting features & writing to csv file
fout = open(outputPathCSV,'w')
row = 1
for flow in flowList:
	featureRow = extractFeatures(packets,flow) 
	#writing feature
	tmp = ''
	for item in featureRow:
		if tmp == '':
			tmp += str(item)
		else:
			tmp += ',' + str(item)
	fout.write(application + ',' + tmp + '\n')	 
	row += 1

fout.close()








	
