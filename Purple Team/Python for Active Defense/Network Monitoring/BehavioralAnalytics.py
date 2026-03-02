import psutil
import logging
import time

# Configuração de logging
logging.basicConfig(filename='process_network_activity.log', level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Dicionário para armazenar os dados de conexões de processos
conn_counts = {}

# Função para construir a linha de base de processos e suas conexões de rede
def buildBaseline():
    logging.info("Building baseline for process network activity.")
    for p in psutil.pids():
        try:
            proc = psutil.Process(p)
            name = proc.name()
            hasConns = int(len(proc.connections()) > 0)
            if name in conn_counts:
                (connected, total) = conn_counts[name]
                conn_counts[name] = (connected + hasConns, total + 1)
            else:
                conn_counts[name] = (hasConns, 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logging.error(f"Error accessing process {p}: {e}")
            continue

# Função para verificar as conexões de rede dos processos
def checkConnections(threshold=0.5):
    logging.info("Checking network connections for processes.")
    for p in psutil.pids():
        try:
            proc = psutil.Process(p)
            name = proc.name()
            hasConns = len(proc.connections()) > 0
            if hasConns:
                if name in conn_counts:
                    (connected, total) = conn_counts[name]
                    prob = connected / total
                    if prob < threshold:
                        logging.warning(f"Process {name} has network connection at {prob:.2f} probability")
            else:
                if name in conn_counts:
                    (connected, total) = conn_counts[name]
                    prob = 1 - (connected / total)
                    if prob < threshold:
                        logging.warning(f"Process {name} doesn't have network connection at {prob:.2f} probability")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logging.error(f"Error accessing process {p}: {e}")
            continue

def main():
    # Construa a linha de base e depois faça a verificação das conexões
    buildBaseline()
    time.sleep(5)  # Adiciona um intervalo entre a coleta da linha de base e a verificação
    checkConnections()

if __name__ == "__main__":
    main()
