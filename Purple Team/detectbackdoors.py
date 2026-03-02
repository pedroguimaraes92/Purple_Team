import psutil
import time
import subprocess
import logging
import os

# Configuração do logger
logging.basicConfig(
    filename="monitoramento.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Configurações de segurança
PORTAS_LEGITIMAS = [22, 80, 443]  # Exemplo: SSH, HTTP, HTTPS
PROCESSOS_LEGITIMOS = ["rpcbind", "svchost.exe"]  # Processos confiáveis
FAIXA_PORTAS_RPC = range(50000, 60000)  # Faixa de portas dinâmica para RPC

def listar_conexoes():
    conexoes = []
    for conexao in psutil.net_connections(kind="inet"):
        if conexao.status == psutil.CONN_LISTEN:
            conexoes.append({
                "porta": conexao.laddr.port,
                "processo": psutil.Process(conexao.pid).name() if conexao.pid else "Desconhecido",
                "caminho_processo": psutil.Process(conexao.pid).exe() if conexao.pid else "Desconhecido",
                "ip_remoto": conexao.raddr.ip if conexao.raddr else "N/A",
            })
    return conexoes

def registrar_log(mensagem, nivel="INFO"):
    if nivel == "INFO":
        logging.info(mensagem)
    elif nivel == "ALERTA":
        logging.warning(mensagem)
    elif nivel == "ERRO":
        logging.error(mensagem)

def fechar_conexao(ip_remoto, porta):
    try:
        if ip_remoto != "N/A":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_remoto, "-j", "DROP"], check=True)
            print(f"[AÇÃO] Conexão bloqueada: IP {ip_remoto} na porta {porta}")
            registrar_log(f"Conexão bloqueada: IP {ip_remoto} na porta {porta}", nivel="ALERTA")
    except Exception as e:
        print(f"[ERRO] Falha ao bloquear conexão: {e}")
        registrar_log(f"Erro ao bloquear conexão: {e}", nivel="ERRO")

def verificar_portas():
    conexoes = listar_conexoes()
    for conexao in conexoes:
        porta = conexao["porta"]
        processo = conexao["processo"]
        caminho_processo = conexao["caminho_processo"]

        if processo in PROCESSOS_LEGITIMOS or porta in PORTAS_LEGITIMAS or porta in FAIXA_PORTAS_RPC:
            continue

        print(f"[ALERTA] Porta não autorizada detectada: {porta}")
        print(f" -> Processo: {processo}")
        print(f" -> Caminho do Processo: {caminho_processo}")
        print(f" -> IP remoto: {conexao['ip_remoto']}")
        print("-" * 40)
        registrar_log(f"Conexão suspeita detectada: IP {conexao['ip_remoto']}, Porta {porta}", nivel="ALERTA")
        fechar_conexao(conexao["ip_remoto"], porta)

def monitorar_suricata(log_path="/var/log/suricata/fast.log"):
    if os.path.exists(log_path):
        with open(log_path, "r") as log_file:
            for linha in log_file:
                print(f"[SURICATA ALERT] {linha.strip()}")
                registrar_log(f"SURICATA ALERT: {linha.strip()}", nivel="ALERTA")
    else:
        print("[ERRO] Arquivo de log do Suricata não encontrado.")

def monitorar():
    print("Monitorando portas abertas... (Ctrl+C para interromper)")
    while True:
        try:
            verificar_portas()
            time.sleep(10)
        except KeyboardInterrupt:
            print("\nMonitoramento encerrado.")
            break
        except Exception as e:
            print(f"[ERRO] {e}")
            registrar_log(f"Erro no monitoramento: {e}", nivel="ERRO")

if __name__ == "__main__":
    monitorar()
