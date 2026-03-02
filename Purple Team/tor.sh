#!/bin/bash

# Instala Tor
if ! command -v tor >/dev/null 2>&1; then
    echo "[*] Instalando Tor..."
    apt update && apt install -y tor
fi

# Inicia Tor
echo "[*] Iniciando Tor..."
systemctl start tor
systemctl enable tor
sleep 3

# Configura torrc para TransPort + DNSPort
TORRC="/etc/tor/torrc"
if ! grep -q "TransPort 9040" $TORRC; then
    echo "[*] Configurando torrc para TransPort e DNSPort..."
    echo -e "\nVirtualAddrNetworkIPv4 10.192.0.0/10\nAutomapHostsOnResolve 1\nTransPort 9040\nDNSPort 5353" >> $TORRC
    systemctl restart tor
    sleep 3
fi

# Bloqueia IPv6 para evitar vazamento
echo "[*] Bloqueando IPv6 temporariamente..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Iptables para redirecionar TCP/DNS
USER_ID=$(id -u)
echo "[*] Criando regras de iptables para usuário $USER_ID..."
iptables -t nat -F
iptables -t nat -A OUTPUT -m owner --uid-owner $USER_ID -p tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A OUTPUT -m owner --uid-owner $USER_ID -p udp --dport 53 -j REDIRECT --to-ports 5353

# Teste IP Tor-friendly
echo "[*] Testando IP pelo Tor..."
TOR_IP=$(curl -4 -s http://check.torproject.org/api/ip | grep -oP '"IP":\s*"\K[^"]+')
if [ -z "$TOR_IP" ]; then
    echo "[!] Falha ao detectar IP Tor. Pode ser exit node instável."
else
    echo "[*] IP Tor detectado: $TOR_IP"
fi

# Abre bash roteado pelo Tor
echo "[*] Bash roteado pelo Tor com sucesso."
echo "[*] Para sair, digite 'exit'."
bash
