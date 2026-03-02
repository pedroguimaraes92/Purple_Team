from scapy.all import *
import time

# IPs e portas de decoy
decoys = {
    "127.0.0.1": [443, 8443],
    "10.10.10.8": [443, 8443]
}

def analyzePackets(p):
    if p.haslayer(IP):
        src_ip, dst_ip = p[IP].src, p[IP].dst
        if src_ip in decoys or dst_ip in decoys:
            ports = []
            if p.haslayer(TCP):
                ports = [p[TCP].sport, p[TCP].dport]
            elif p.haslayer(UDP):
                ports = [p[UDP].sport, p[UDP].dport]
            if any(port in decoys.get(src_ip, []) or port in decoys.get(dst_ip, []) for port in ports):
                wrpcap("out.pcap", p, append=True)

# Filtro para capturar pacotes apenas nas portas de interesse
sniff(filter="tcp port 443 or udp port 8443", prn=analyzePackets)
