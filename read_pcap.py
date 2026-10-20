from scapy.all import rdpcap

packets = rdpcap("sample.pcapng")
print(len(packets))