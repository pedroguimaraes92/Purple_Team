import os
import logging
import winreg

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logon_script.log"),
        logging.StreamHandler()
    ]
)

def get_current_user_sid():
    """Obtém o SID do usuário logado."""
    try:
        import ctypes
        from ctypes.wintypes import MAX_PATH
        
        sid_buffer = ctypes.create_unicode_buffer(MAX_PATH)
        sid_size = ctypes.c_ulong(MAX_PATH)
        ctypes.windll.advapi32.GetUserNameW(sid_buffer, ctypes.byref(sid_size))
        
        username = sid_buffer.value
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as key:
            for i in range(winreg.QueryInfoKey(key)[0]):  # Itera os SIDs
                sid = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, sid) as subkey:
                    try:
                        profile = winreg.QueryValueEx(subkey, "ProfileImagePath")[0]
                        if username in profile:
                            return sid
                    except FileNotFoundError:
                        continue
        logging.error("Não foi possível determinar o SID do usuário atual.")
        return None
    except Exception as e:
        logging.error(f"Erro ao obter SID: {e}")
        return None

def set_logon_script(path, dry_run=False):
    """Configura um script de logon para o usuário atual."""
    try:
        sid = get_current_user_sid()
        if not sid:
            return False

        regpath = f"{sid}\\Environment"

        if dry_run:
            logging.info(f"[DRY-RUN] Simulando configuração de script '{path}' em {regpath}.")
            return True

        with winreg.ConnectRegistry(None, winreg.HKEY_USERS) as reg:
            with winreg.OpenKey(reg, regpath, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "UserInitMprLogonScript", 0, winreg.REG_SZ, path)
                logging.info(f"Script de logon configurado com sucesso para o SID {sid}.")
        return True
    except PermissionError:
        logging.error("Permissões insuficientes para modificar o registro. Execute como administrador.")
        return False
    except Exception as e:
        logging.error(f"Erro ao configurar script de logon: {e}")
        return False

def main():
    """Função principal."""
    # Caminho do executável
    filedir = os.path.join(os.getcwd(), "Temp")
    filename = "benign.exe"
    filepath = os.path.join(filedir, filename)

    # Criação do diretório e remoção de arquivo antigo
    os.makedirs(filedir, exist_ok=True)
    if os.path.isfile(filepath):
        os.remove(filepath)

    # Simula criação de executável (substitua com sua lógica)
    logging.info("Simulando criação de executável benigno.")
    with open(filepath, "w") a
