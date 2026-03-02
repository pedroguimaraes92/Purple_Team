import os
import winreg
import logging

# Configuração de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def readPathValue(reghive, regpath):
    try:
        reg = winreg.ConnectRegistry(None, reghive)
        key = winreg.OpenKey(reg, regpath, access=winreg.KEY_READ)
        index = 0
        while True:
            val = winreg.EnumValue(key, index)
            if val[0] == "Path":
                return val[1]
            index += 1
    except FileNotFoundError as e:
        logging.error(f"Erro ao acessar o registro: {e}")
        return None

def editPathValue(reghive, regpath, targetdir):
    path = readPathValue(reghive, regpath)
    if path is None:
        logging.error("A variável de ambiente Path não foi encontrada.")
        return False

    # Verificar se o diretório já está no Path
    if targetdir in path:
        logging.info(f"O diretório '{targetdir}' já está no Path.")
        return False

    # Adiciona o novo diretório ao Path
    newpath = targetdir + ";" + path
    try:
        reg = winreg.ConnectRegistry(None, reghive)
        key = winreg.OpenKey(reg, regpath, 0, access=winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, newpath)
        logging.info(f"Diretório '{targetdir}' adicionado ao Path com sucesso.")
        return True
    except PermissionError:
        logging.error("Permissões insuficientes para modificar o registro. Execute como administrador.")
        return False
    except Exception as e:
        logging.error(f"Erro ao modificar o registro: {e}")
        return False

def main():
    targetdir = os.getcwd()
    
   
