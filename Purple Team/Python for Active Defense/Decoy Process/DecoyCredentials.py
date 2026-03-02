import asyncio
import asyncssh
import sys
import bcrypt
import logging
import json
from collections import defaultdict
from time import time
from logging.handlers import RotatingFileHandler

# Configurações gerais
PORT = 8022
MAX_FAILED_ATTEMPTS = 3
BLOCK_TIME = 60  # Segundos
USER_DATA_FILE = "users.json"
BLOCKLIST_FILE = "blocklist.json"
LOG_FILE = "ssh_server.log"

# Configuração de logs
logger = logging.getLogger("SSHServer")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Carregar usuários e bloqueios
def load_data(file, default):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_data(file, data):
    with open(file, "w") as f:
        json.dump(data, f)

USERS = load_data(USER_DATA_FILE, {
    "admin": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode(),
    "user": bcrypt.hashpw("mypassword".encode(), bcrypt.gensalt()).decode(),
})
blocked_ips = load_data(BLOCKLIST_FILE, defaultdict(lambda: 0))
failed_logins = defaultdict(int)

# Função para verificar senhas
def validate_password(username, password):
    hashed_password = USERS.get(username)
    if hashed_password:
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    return False

# Classe do servidor SSH
class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn
        self.ip_address = self._conn.get_extra_info('peername')[0]

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        global blocked_ips, failed_logins

        # Verificar bloqueio de IP
        if blocked_ips.get(self.ip_address, 0) > time():
            logger.warning(f"Conexão rejeitada de {self.ip_address} (bloqueado).")
            raise asyncssh.DisconnectError(10, "Seu IP está temporariamente bloqueado devido a falhas de login.")

        # Validar credenciais
        if validate_password(username, password):
            logger.info(f"Login bem-sucedido de {self.ip_address} (usuário: {username}).")
            failed_logins[self.ip_address] = 0
            save_data(BLOCKLIST_FILE, blocked_ips)
            return True

        # Registro de falhas
        failed_logins[self.ip_address] += 1
        logger.warning(f"Tentativa de login falhada de {self.ip_address} (usuário: {username}). Total: {failed_logins[self.ip_address]}")

        # Bloquear IP após falhas consecutivas
        if failed_logins[self.ip_address] >= MAX_FAILED_ATTEMPTS:
            blocked_ips[self.ip_address] = time() + BLOCK_TIME
            save_data(BLOCKLIST_FILE, blocked_ips)
            logger.warning(f"IP {self.ip_address} bloqueado por {BLOCK_TIME} segundos.")

        raise asyncssh.DisconnectError(10, "Nome de usuário ou senha incorretos.")

    def connection_lost(self, exc):
        logger.info(f"Conexão encerrada: {self.ip_address}.")

# Gerenciamento do processo do cliente
async def handle_client(process):
    process.write("Bem-vindo ao servidor SSH!\n")
    process.exit(0)

# Inicialização do servidor
async def start_server():
    try:
        await asyncssh.create_server(
            MySSHServer, '', PORT,
            server_host_keys=['ssh_host_key'],
            process_factory=handle_client
        )
        logger.info(f"Servidor SSH iniciado na porta {PORT}.")
    except (OSError, asyncssh.Error) as exc:
        logger.error(f"Erro ao iniciar o servidor: {exc}")
        sys.exit(1)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server())
    except (OSError, asyncssh.Error) as exc:
        logger.error(f"Erro ao iniciar o servidor: {exc}")
        sys.exit(1)
    loop.run_forever()
