from scapy.all import *
import logging
import csv
from datetime import datetime
from collections import defaultdict

# Configuração de logging
logging.basicConfig(filename='flow_analysis.log', level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Dicionário para armazenar os fluxos de tráfego
flowData = defaultdict(lambda: {'bytes_sent': 0, 'bytes_received': 0, 'pkt_sent': 0, 'pkt_received': 0, 'protocols': set()})

# Função para analisar o fluxo de pacotes
def analyzeFlow(p):
    if p.haslayer(IP):
        length = len(p)
        src = p[IP].src
        dst = p[IP].dst
        protocol = p[IP].proto

        # Filtra pacotes TCP/UDP para análise mais detalhada
        if protocol == 6:  # TCP
            protocol_name = 'TCP'
        elif protocol == 17:  # UDP
            protocol_name = 'UDP'
        else:
            protocol_name = 'OTHER'

        # Cria chave para fluxo bidirecional
        key = f"{min(src, dst)},{max(src, dst)}"
        
        if src < dst:
            flowData[key]['bytes_sent'] += length
            flowData[key]['pkt_sent'] += 1
        else:
            flowData[key]['bytes_received'] += length
            flowData[key]['pkt_received'] += 1

        # Adiciona o protocolo ao fluxo
        flowData[key]['protocols'].add(protocol_name)

# Função para capturar pacotes em tempo real
def capturePackets(interface="eth0", count=100):
    sniff(iface=interface, prn=analyzeFlow, count=count, store=False)

# Função para detectar anomalias em fluxos (exemplo: tráfego excessivo)
def checkAnomalies():
    for key, flow in flowData.items():
        # Definir um limite arbitrário para um número alto de pacotes em um curto período
        if flow['pkt_sent'] > 1000 or flow['pkt_received'] > 1000:
            logging.warning(f"Anomaly detected: High packet count for flow {key} ({flow['pkt_sent']} sent, {flow['pkt_received']} received)")

# Função para imprimir os resultados na tela
def printResults():
    print(f"{'Source IP':<15} {'Destination IP':<15} {'Bytes Sent':<10} {'Bytes Received':<15} {'Packets Sent':<15} {'Packets Received':<15} {'Protocols'}")
    for key, flow in flowData.items():
        src, dst = key.split(",")
        protocols = ', '.join(flow['protocols'])
        print(f"{src:<15} {dst:<15} {flow['bytes_sent']:<10} {flow['bytes_received']:<15} {flow['pkt_sent']:<15} {flow['pkt_received']:<15} {protocols}")

# Função para salvar os resultados em um arquivo CSV
def saveResultsToCSV():
    with open('flow_analysis.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Source IP", "Destination IP", "Bytes Sent", "Bytes Received", "Packets Sent", "Packets Received", "Protocols"])
        for key, flow in flowData.items():
            src, dst = key.split(",")
            protocols = ', '.join(flow['protocols'])
            writer.writerow([src, dst, flow['bytes_sent'], flow['bytes_received'], flow['pkt_sent'], flow['pkt_received'], protocols])
    logging.info("Results saved to flow_analysis.csv")

# Função principal para monitoramento contínuo
def monitorNetwork(interface="eth0", packet_count=100, anomaly_threshold=1000):
    logging.info("Starting network monitoring...")
    capturePackets(interface, packet_count)
    checkAnomalies()
    printResults()
    saveResultsToCSV()

if __name__ == "__main__":
    # Defina os parâmetros para monitoramento
    interface = "eth0"  # Interface de rede a ser monitorada
    packet_count = 100  # Número de pacotes a serem capturados
    anomaly_threshold = 1000  # Limite para detecção de tráfego anômalo

    # Inicia o monitoramento
    monitorNetwork(interface, packet_count, anomaly_threshold)
