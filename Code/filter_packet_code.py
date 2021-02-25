'''
This code can be used for define new rules. 
'''



from scapy.all import *

#reading from pcap file
packets = rdpcap('facebook_2.pcap.pcapng')
filtered_packets =  PacketList()

# Filter-Rules: 
# 91.189.91.13, 91.189.91.14, 91.189.91.15, more ==> us.archive.ubuntu.com
# 91.189.88.161, 91.189.92.181, 91.189.92.200  ==> security.ubuntu.com
# 91.189.95.83 ==> ppa.launchpad.net
# 91.189.92.152 ==> extras.ubuntu.com
   
ignore_list = ['239.255.255.250','91.189.88.161','91.189.92.181','91.189.91.13','91.189.91.14','91.189.91.15', '91.189.95.83', '91.189.92.152']

num = -1
for pk in packets:

	num = num + 1
	if not pk.haslayer(IP):
		print 'packet without IP: ', num
		continue

	if not (pk['IP'].src in ignore_list or pk['IP'].dst in ignore_list):
		filtered_packets.append(pk)


#writing to pcap file
wrpcap('filtered.pcap.pcapng',filtered_packets) 

print 'Packets count in original pcap =  ', len(packets)
print 'Packets count in filtered pcap =  ', len(filtered_packets)

