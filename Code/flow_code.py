from scapy.all import *
import pickle
import os 
from math import sqrt

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

	
	#3
	minfpktl, maxfpktl, meanfpktl, stdfpktl, fpackets,  fbytes,  minfiat, maxfiat, meanfiat, stdfiat = DirectionFeatures(packets, flow, "Forward")
	featureVector.append(minfpktl)
	featureVector.append(maxfpktl)
	featureVector.append(meanfpktl)
	featureVector.append(stdfpktl)
	featureVector.append(fpackets)
	featureVector.append(fbytes)
	featureVector.append(minfiat)
	featureVector.append(maxfiat)
	featureVector.append(meanfiat)
	featureVector.append(stdfiat)
	
	minbpktl, maxbpktl, meanbpktl, stdbpktl, bpackets,  bbytes,  minbiat, maxbiat, meanbiat, stdbiat = DirectionFeatures(packets, flow, "Backward")
	featureVector.append(minbpktl)
	featureVector.append(maxbpktl)
	featureVector.append(meanbpktl)
	featureVector.append(stdbpktl)
	featureVector.append(bpackets)
	featureVector.append(bbytes)
	featureVector.append(minbiat)
	featureVector.append(maxbiat)
	featureVector.append(meanbiat)
	featureVector.append(stdbiat)
	
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



def DirectionFeatures(packets, flow, direction):  
	
	# Reference: papers/p5-williams.pdf

	# Minimum packet length in specified direction  		 			------------->  minpktl
	# Maximum packet length in specified direction    		 			------------->	maxpktl
	# Mean packet length packet length in specified direction   		------------->	meanpktl
	# Standard deviation of packet length in specified direction  		------------->	stdpktl
	# Number of packets in specified direction    						------------->	numpackets
	# Number of bytes in specified direction    						------------->	sizebytes
	# Minimum packet inter-arrival time in specified direction			------------->	miniat
	# Maximum packet inter-arrival time in specified direction   		------------->	maxiat
	# Mean inter-arrival time in specified direction   					------------->	meaniat
	# Standard deviation of inter arrival time in specified direction   ------------->	stdiat
	

	pktlength = []
	pkttime = []
	
	if direction == "Forward" :
		source = packets[flow[2][0]][IP].src
	else :
		source = packets[flow[2][0]][IP].dst
	
	minpktl = 0
	maxpktl = 0
	meanpktl = 0
	stdpktl = 0
	numpackets = 0
	sizebytes = 0
	miniat = 0
	maxiat = 0
	meaniat = 0
	stdiat = 0
	
	timelastpacket = 0
	timecurpacket = 0
	lasttimeflag = True
	
	for pktNumber in flow[2]:
		if packets[pktNumber][IP].src == source:
			pktlength.append(packets[pktNumber][IP].len)
			
			if lasttimeflag is True:
				timelastpacket = packets[pktNumber].time
				lasttimeflag = False
			else :
				timedif = (packets[pktNumber].time - timelastpacket) / 1000
				timelastpacket = packets[pktNumber].time
				pkttime.append(timedif)
			
	try:
		minpktl = min(pktlength)
	except (ValueError, TypeError):
		minpktl = 0
	
	try:
		maxpktl = max(pktlength)
	except (ValueError, TypeError):
		maxpktl = 0
	
	try:
		meanpktl =  mean(pktlength)
	except (ValueError, TypeError, ZeroDivisionError):
		meanpktl = 0
	
	try:
		stdpktl =  stddev(pktlength)
	except (ValueError, TypeError, ZeroDivisionError):
		stdpktl = 0
	
	try:
		numpackets = len(pktlength)
	except (ValueError, TypeError):
		numpackets = 0
	
	try:
		sizebytes = sum(pktlength)
	except (ValueError, TypeError):
		sizebytes = 0
	
	try:
		miniat = min(pkttime)
	except (ValueError, TypeError):
		miniat = 0
	
	try:
		maxiat = max(pkttime)
	except (ValueError, TypeError):
		maxiat = 0
	
	try:
		meaniat =  mean(pkttime)
	except (ValueError, TypeError, ZeroDivisionError):
		meaniat = 0
	
	try:
		stdiat =  stddev(pkttime)
	except (ValueError, TypeError, ZeroDivisionError):
		stdiat = 0
	
	return minpktl, maxpktl, meanpktl, stdpktl, numpackets,  sizebytes,  miniat, maxiat, meaniat, stdiat    			 


def mean(lst):
	"""returns the mean of lst"""
    	return float(sum(lst) / len(lst))

def stddev(lst):
	"""returns the standard deviation of lst"""
	mn = mean(lst)
    	variance = sum([(e-mn)**2 for e in lst]) / len(lst)
    	return sqrt(variance)



#######################  main code ################################

#variables
application = 'faceboook'
pcapFilePath = 'filtered.pcap.pcapng'
flowPicklePath = 'flows.pik'   # this is optional parameter..   if not required then set it to None [ ex: flowPicklePath = None ]
outputPathCSV = 'out_features.csv'


#reading pcap file
print('parsing pcap started...')
packets = rdpcap(pcapFilePath)
print('parsing complete...')

#extracting flow
flowList = extractFlows(packets,flowPicklePath)       
#print flowList
print('Total packets = ', len(packets))
print('Total no flows = ', len(flowList))

#print('Packet Interarrival time = ',(packets[1].time - packets[0].time)/1000)


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








	
